#!/usr/bin/env bash
#
# lib/protocol/netbios/nbt.sh — NetBIOS over TCP/IP (NBT) — RFC 1001/1002
#
# NBT est la couche de session utilisée par SMB1 (port 139).
# SMB2/3 utilise le "Direct TCP Transport" (port 445) avec un header
# simplifié, mais NBT reste nécessaire pour les environnements mixtes.
#
# Ce module implémente :
#   - Session Request / Session Positive/Negative Response (port 139)
#   - NBT Session Message (enveloppe de tout paquet SMB sur port 139)
#   - Encodage/décodage des noms NetBIOS (First Level Encoding)
#
# Référence : RFC 1001 (concepts), RFC 1002 (spécifications)
#
# Dépendances : core/hex, core/bytes, core/endian, core/log, transport/tcp
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_NBT:-}" ]] && return 0
readonly _ENSH_PROTO_NBT=1

ensh::import core/hex
ensh::import core/bytes
ensh::import core/endian
ensh::import core/log
ensh::import transport/tcp

# ── Types de paquets NBT (RFC 1002 §4.3.1) ───────────────────────────────────

readonly NBT_TYPE_SESSION_MESSAGE=0x00
readonly NBT_TYPE_SESSION_REQUEST=0x81
readonly NBT_TYPE_POS_SESSION_RESP=0x82
readonly NBT_TYPE_NEG_SESSION_RESP=0x83
readonly NBT_TYPE_RETARGET_RESP=0x84
readonly NBT_TYPE_KEEPALIVE=0x85

# ── Encodage du nom NetBIOS (First Level Encoding, RFC 1002 §4.1) ─────────────

# nbt::encode_name <name_15chars> <suffix_byte_hex> <var_out>
#
# Encode un nom NetBIOS de 15 caractères + 1 octet suffixe en
# "First Level Encoding" (chaque nibble → lettre A-P).
#
# Exemple : "WORKGROUP       " + 0x00 → "EGFCEFEECACACACACACACACACACACACA" + "AA"
#
# La structure finale : longueur (0x20) + 32 octets encodés + terminateur 0x00 + scope 0x00
nbt::encode_name() {
    local name="$1"
    local suffix="${2:-00}"
    local -n _nbt_en_out="$3"

    # Padder/tronquer à 15 caractères
    printf -v name '%-15.15s' "${name}"

    # Convertir en majuscules
    name="${name^^}"

    # Construire les 16 octets (15 chars + 1 suffixe)
    local bytes_hex
    hex::from_string "${name}" bytes_hex
    bytes_hex+="${suffix^^}"

    # First Level Encoding : chaque nibble → A + nibble_value
    _nbt_en_out="20"   # longueur = 32 (0x20) nibbles encodés

    local -i i nibble_hi nibble_lo
    for (( i=0; i<${#bytes_hex}; i+=2 )); do
        nibble_hi=$(( 16#${bytes_hex:${i}:1} ))
        nibble_lo=$(( 16#${bytes_hex:$(( i+1 )):1} ))
        printf -v _nbt_en_out '%s%02X%02X' \
            "${_nbt_en_out}" \
            "$(( 0x41 + nibble_hi ))" \
            "$(( 0x41 + nibble_lo ))"
    done

    _nbt_en_out+="00"  # terminateur de label
    _nbt_en_out+="00"  # terminateur de scope (racine)
}

# nbt::decode_name <encoded_hex> <var_name_out> <var_suffix_out>
#
# Décode un nom NetBIOS encodé en First Level Encoding.
nbt::decode_name() {
    local enc="${1^^}"
    local -n _nbt_dn_name="$2"
    local -n _nbt_dn_suffix="$3"

    # Sauter l'octet de longueur (0x20 = 32)
    local encoded="${enc:2:64}"   # 32 octets encodés = 64 nibbles

    local raw_hex=""
    local -i i
    for (( i=0; i<${#encoded}; i+=4 )); do
        local hi=$(( 16#${encoded:${i}:2} - 0x41 ))
        local lo=$(( 16#${encoded:$(( i+2 )):2} - 0x41 ))
        printf -v raw_hex '%s%01X%01X' "${raw_hex}" "${hi}" "${lo}"
    done

    # Séparer les 15 caractères du suffixe
    local name_hex="${raw_hex:0:30}"
    _nbt_dn_suffix="${raw_hex:30:2}"

    hex::to_string "${name_hex}" _nbt_dn_name
    # Supprimer le padding de droite
    _nbt_dn_name="${_nbt_dn_name%% }"
    _nbt_dn_name="${_nbt_dn_name%%  *}"
}

# ── Header NBT ────────────────────────────────────────────────────────────────

# nbt::make_header <type_byte_hex> <length_int> <var_out>
#
# Construit un header NBT de 4 octets :
#   Type    : 1 octet
#   Flags   : 1 octet (toujours 0x00 pour Session Message)
#   Length  : 2 octets big-endian
nbt::make_header() {
    local type_hex="${1^^}"
    local -i length="$2"
    local -n _nbt_mh_out="$3"
    local len_be
    endian::be16 "${length}" len_be
    _nbt_mh_out="${type_hex}00${len_be}"
}

# nbt::parse_header <hex_4bytes> <var_type_out> <var_flags_out> <var_length_out>
#
# Parse un header NBT de 4 octets.
nbt::parse_header() {
    local hdr="${1^^}"
    local -n _nbt_ph_type="$2"
    local -n _nbt_ph_flags="$3"
    local -n _nbt_ph_len="$4"

    _nbt_ph_type="${hdr:0:2}"
    _nbt_ph_flags="${hdr:2:2}"
    endian::read_be16 "${hdr}" 2 _nbt_ph_len
}

# ── Session Request (port 139) ────────────────────────────────────────────────

# nbt::session_request <tcp_handle> <called_name> <calling_name> <var_result_out>
#
# Envoie un NBT Session Request et vérifie la réponse.
# <called_name>  : nom NetBIOS du serveur cible (ex: "SERVERNAME")
# <calling_name> : nom NetBIOS du client (ex: "WORKSTATION")
# Retourne 0 si le serveur accepte la session.
nbt::session_request() {
    local handle="$1"
    local called_name="$2"
    local calling_name="$3"
    local -n _nbt_sr_out="$4"

    # Encoder les noms
    local called_enc calling_enc
    nbt::encode_name "${called_name}"  "20" called_enc   # suffixe 0x20 = Server
    nbt::encode_name "${calling_name}" "00" calling_enc  # suffixe 0x00 = Workstation

    # Payload = called + calling
    local payload="${called_enc}${calling_enc}"
    local -i payload_len=$(( ${#payload} / 2 ))

    # Header NBT Session Request
    local header
    nbt::make_header "${NBT_TYPE_SESSION_REQUEST}" "${payload_len}" header

    log::debug "nbt::session_request : called='${called_name}', calling='${calling_name}'"

    # Envoyer
    tcp::send "${handle}" "${header}${payload}" || return 1

    # Lire la réponse (4 octets de header)
    local resp_hdr
    tcp::recv "${handle}" 4 resp_hdr || return 1

    local resp_type resp_flags resp_len
    nbt::parse_header "${resp_hdr}" resp_type resp_flags resp_len

    case "0x${resp_type}" in
        0x82)   # Positive Session Response
            log::info "nbt : session établie avec '${called_name}'"
            _nbt_sr_out="OK"
            return 0
            ;;
        0x83)   # Negative Session Response
            local reason_hex
            tcp::recv "${handle}" "${resp_len}" reason_hex
            log::error "nbt : session refusée (raison=0x${reason_hex})"
            _nbt_sr_out="REFUSED:${reason_hex}"
            return 1
            ;;
        0x84)   # Retarget Response
            local retarget_data
            tcp::recv "${handle}" "${resp_len}" retarget_data
            log::warn "nbt : retarget vers ${retarget_data}"
            _nbt_sr_out="RETARGET:${retarget_data}"
            return 1
            ;;
        *)
            log::error "nbt : type de réponse inattendu 0x${resp_type}"
            _nbt_sr_out="UNKNOWN:${resp_type}"
            return 1
            ;;
    esac
}

# ── Envoi/réception de messages NBT ──────────────────────────────────────────

# nbt::send_message <tcp_handle> <hex_payload>
#
# Encapsule un payload (ex: paquet SMB) dans un NBT Session Message et l'envoie.
nbt::send_message() {
    local handle="$1"
    local payload="${2^^}"
    local -i plen=$(( ${#payload} / 2 ))

    local header
    nbt::make_header "${NBT_TYPE_SESSION_MESSAGE}" "${plen}" header

    log::trace "nbt::send_message : ${plen} octets"
    tcp::send "${handle}" "${header}${payload}"
}

# nbt::recv_message <tcp_handle> <var_out> [timeout]
#
# Reçoit un NBT Session Message et retourne son payload.
# Gère automatiquement les Keepalive en les ignorant.
nbt::recv_message() {
    local handle="$1"
    local -n _nbt_rm_out="$2"
    local -i timeout="${3:-30}"

    while true; do
        # Lire le header NBT (4 octets)
        local hdr
        tcp::recv "${handle}" 4 hdr "${timeout}" || return 1

        local pkt_type pkt_flags pkt_len
        nbt::parse_header "${hdr}" pkt_type pkt_flags pkt_len

        if [[ "0x${pkt_type}" == "0x85" ]]; then
            log::trace "nbt : keepalive reçu, ignoré"
            continue
        fi

        if [[ "0x${pkt_type}" != "0x00" ]]; then
            log::warn "nbt::recv_message : type inattendu 0x${pkt_type}"
            return 1
        fi

        if (( pkt_len == 0 )); then
            _nbt_rm_out=""
            return 0
        fi

        tcp::recv "${handle}" "${pkt_len}" _nbt_rm_out "${timeout}"
        return $?
    done
}

# ── Connexion complète NBT (port 139) ─────────────────────────────────────────

# nbt::connect <host> <called_name> <calling_name> <var_handle_out> [port]
#
# Etablit une connexion TCP et négocie une session NBT.
# <port> par défaut : 139
nbt::connect() {
    local host="$1"
    local called_name="$2"
    local calling_name="$3"
    local -n _nbt_conn_out="$4"
    local -i port="${5:-139}"

    local handle
    tcp::connect "${host}" "${port}" handle || return 1

    local result
    nbt::session_request "${handle}" "${called_name}" "${calling_name}" result || {
        tcp::close "${handle}"
        return 1
    }

    _nbt_conn_out="${handle}"
}
