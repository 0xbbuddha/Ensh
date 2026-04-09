#!/usr/bin/env bash
#
# lib/transport/udp.sh — Transport UDP via /dev/udp
#
# Fournit une interface pour envoyer et recevoir des datagrammes UDP.
# UDP étant sans connexion, le modèle est simplifié : on ouvre un socket
# vers une destination, on envoie, on lit la réponse.
#
# Note : /dev/udp dans Bash est limité à l'envoi (send-only sur certains
# systèmes). La réception via un FD /dev/udp n'est pas toujours fiable.
# Pour des protocoles nécessitant une réception UDP robuste (ex: DNS, NBNS),
# envisager de passer par nc/ncat si disponible, ou utiliser une socket TCP
# de repli quand le protocole le permet.
#
# Dépendances : core/log, core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_TRANSPORT_UDP:-}" ]] && return 0
readonly _ENSH_TRANSPORT_UDP=1

ensh::import core/log
ensh::import core/hex

declare -gA _UDP_HOST=()
declare -gA _UDP_PORT=()
declare -gi _UDP_NEXT_FD=50

# ── Envoi d'un datagramme ─────────────────────────────────────────────────────

# udp::send <host> <port> <hex_data>
#
# Ouvre un socket UDP, envoie les données et le referme.
# Modèle fire-and-forget : pas de garantie de livraison.
udp::send() {
    local host="$1"
    local -i port="$2"
    local hex="${3^^}"
    local -i fd="${_UDP_NEXT_FD}"
    (( _UDP_NEXT_FD++ ))

    log::trace "udp::send ${#hex} nibbles → ${host}:${port}"

    if ! eval "exec ${fd}>/dev/udp/${host}/${port}" 2>/dev/null; then
        log::error "udp::send : impossible d'ouvrir /dev/udp/${host}/${port}"
        return 1
    fi

    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        printf "\\x${hex:${i}:2}"
    done >&"${fd}"

    eval "exec ${fd}>&-"
}

# udp::send_recv <host> <port> <hex_data> <var_out> [timeout_seconds] [max_bytes]
#
# Envoie un datagramme et attend une réponse.
# La réponse est stockée en hexadécimal dans <var_out>.
udp::send_recv() {
    local host="$1"
    local -i port="$2"
    local hex="${3^^}"
    local -n _udp_sr_out="$4"
    local -i timeout="${5:-5}"
    local -i max="${6:-4096}"

    local -i fd_in="${_UDP_NEXT_FD}"
    local -i fd_out=$(( _UDP_NEXT_FD + 1 ))
    (( _UDP_NEXT_FD += 2 ))

    if ! eval "exec ${fd_in}</dev/udp/${host}/${port}" 2>/dev/null; then
        log::error "udp::send_recv : impossible d'ouvrir /dev/udp/${host}/${port}"
        return 1
    fi
    if ! eval "exec ${fd_out}>/dev/udp/${host}/${port}" 2>/dev/null; then
        eval "exec ${fd_in}<&-"
        log::error "udp::send_recv : impossible d'ouvrir l'écriture UDP"
        return 1
    fi

    # Envoi
    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        printf "\\x${hex:${i}:2}"
    done >&"${fd_out}"

    # Réception
    _udp_sr_out=""
    local raw_byte
    local -i received=0

    while (( received < max )); do
        if ! IFS= read -r -d '' -n 1 -t "${timeout}" raw_byte <&"${fd_in}" 2>/dev/null; then
            break
        fi
        if [[ -z "${raw_byte}" ]]; then
            _udp_sr_out+="00"
        else
            printf -v _udp_sr_out '%s%02X' "${_udp_sr_out}" "'${raw_byte}"
        fi
        (( received++ ))
    done

    eval "exec ${fd_in}<&-"
    eval "exec ${fd_out}>&-"

    log::trace "udp::send_recv : ${received} octets reçus de ${host}:${port}"
    [[ -n "${_udp_sr_out}" ]]
}
