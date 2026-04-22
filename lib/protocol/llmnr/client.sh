#!/usr/bin/env bash
#
# lib/protocol/llmnr/client.sh — Client LLMNR (pure bash + socat)
#
# Envoie une requête LLMNR en multicast UDP (224.0.0.252:5355) et retourne
# la réponse parsée. Nécessite socat pour le transport multicast (recvfrom
# non-connecté) ; fallback sur udp::send_recv pour les cibles unicast.
#
# Dépendances : core/log, transport/udp, protocol/llmnr/message
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LLMNR_CLIENT:-}" ]] && return 0
readonly _ENSH_PROTO_LLMNR_CLIENT=1

ensh::import core/log
ensh::import transport/udp
ensh::import protocol/llmnr/message

# ── Helpers binaire ──────────────────────────────────────────────────────────

# _llmnr_client_hex_to_raw <hex> — écrit les octets bruts sur stdout
_llmnr_client_hex_to_raw() {
    local hex="${1^^}"
    local -i i
    for (( i = 0; i < ${#hex}; i += 2 )); do
        printf "\\x${hex:${i}:2}"
    done
}

# _llmnr_client_raw_to_hex — lit des octets bruts sur stdin, retourne hex sur stdout
_llmnr_client_raw_to_hex() {
    od -An -tx1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]'
}

# ── Génération du Transaction ID ─────────────────────────────────────────────

# llmnr::client::_random_txid <var_out>
llmnr::client::_random_txid() {
    local -n _llmnr_ctxid_out="$1"
    _llmnr_ctxid_out=$(od -An -N2 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' | tr '[:lower:]' '[:upper:]')
    if [[ -z "${_llmnr_ctxid_out}" ]]; then
        printf -v _llmnr_ctxid_out '%04X' $(( RANDOM % 65536 ))
    fi
    _llmnr_ctxid_out="${_llmnr_ctxid_out:0:4}"
    [[ -n "${_llmnr_ctxid_out}" ]]
}

# ── Transport socat ──────────────────────────────────────────────────────────

# _llmnr_client_send_recv_socat <host> <port> <hex_data> <timeout_s> [iface] <var_out>
#
# Envoie un datagramme UDP via socat (socket non connecté → recvfrom any peer).
# Utilise UDP4-DATAGRAM qui appelle sendto/recvfrom sans connect().
# Un 'sleep timeout' maintient stdin ouvert le temps que socat reçoive la réponse.
_llmnr_client_send_recv_socat() {
    local host="$1"
    local -i port="$2"
    local hex="${3^^}"
    local -i timeout="$4"
    local iface="${5:-}"
    local -n _llmnr_cssr_out="$6"

    local socat_addr="UDP4-DATAGRAM:${host}:${port},reuseaddr"
    [[ -n "${iface}" ]] && socat_addr+=",interface=${iface}"

    local result
    result=$(
        {
            _llmnr_client_hex_to_raw "${hex}"
            # Maintenir stdin ouvert le temps de recevoir la réponse ;
            # socat ne ferme pas le socket UDP tant que stdin est lisible.
            sleep "${timeout}"
        } | socat -T"${timeout}" - "${socat_addr}" 2>/dev/null | \
        _llmnr_client_raw_to_hex
    )

    _llmnr_cssr_out="${result}"
    [[ -n "${result}" ]]
}

# ── API publique ──────────────────────────────────────────────────────────────

# llmnr::client::query <var_dict_out> <name> [iface] [qtype]
#
# Envoie une requête LLMNR et retourne un dictionnaire bash avec les champs
# parsés (txid, qr, question_name, answer_0_ip, etc.).
# Requiert socat pour les requêtes multicast (réponse unicast d'un pair différent).
# Fallback sur udp::send_recv pour les cibles unicast connues.
llmnr::client::query() {
    local -n _llmnr_cq_out="$1"
    local name="$2"
    local iface="${3:-}"
    local qtype="${4:-A}"

    local server_ip="${ENSH_LLMNR_SERVER_IP:-${LLMNR_MCAST_V4}}"
    local -i port="${ENSH_LLMNR_PORT:-${LLMNR_PORT}}"
    local -i timeout="${ENSH_LLMNR_TIMEOUT:-2}"

    local txid req resp
    llmnr::client::_random_txid txid || {
        log::error "llmnr::client : impossible de générer un txid"
        return 1
    }
    llmnr::message::build_query req "${txid}" "${name}" "${qtype}" || return 1

    if command -v socat >/dev/null 2>&1; then
        if ! _llmnr_client_send_recv_socat "${server_ip}" "${port}" "${req}" "${timeout}" "${iface}" resp; then
            log::warn "llmnr::client : aucune réponse pour '${name}'"
            return 1
        fi
    else
        log::warn "llmnr::client : socat absent, fallback unicast (multicast non garanti)"
        [[ -n "${iface}" ]] && log::warn "llmnr::client : interface ignorée sans socat"
        if ! udp::send_recv "${server_ip}" "${port}" "${req}" resp "${timeout}" 4096; then
            log::warn "llmnr::client : aucune réponse pour '${name}'"
            return 1
        fi
    fi

    llmnr::message::parse "${resp}" _llmnr_cq_out || return 1
    _llmnr_cq_out[raw_response]="${resp}"
    _llmnr_cq_out[request_txid]="${txid}"
    _llmnr_cq_out[server_ip]="${server_ip}"
    _llmnr_cq_out[server_port]="${port}"

    if [[ "${_llmnr_cq_out[txid]}" != "${txid}" ]]; then
        log::warn "llmnr::client : txid inattendu (${_llmnr_cq_out[txid]} != ${txid})"
    fi
}
