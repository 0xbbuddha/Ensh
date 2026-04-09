#!/usr/bin/env bash
#
# lib/transport/tls.sh — Transport TLS via openssl s_client + FIFOs
#
# Implémentation avec deux FIFOs temporaires pour la communication binaire
# bidirectionnelle. Les FIFOs sont ouverts en mode O_RDWR (<>) avant de
# démarrer openssl, ce qui évite tout blocage POSIX (pas besoin d'attendre
# que l'autre bout soit prêt).
#
# Chronologie d'une connexion :
#   1. mkfifo in out        — créer les canaux
#   2. exec {w}<>in         — parent ouvre in en O_RDWR (non bloquant)
#   3. exec {r}<>out        — parent ouvre out en O_RDWR (non bloquant)
#   4. openssl ... <in >out & — openssl ouvre in (O_RDONLY, non bloquant car
#                               w tient l'extrémité écriture) et out (O_WRONLY,
#                               non bloquant car r tient l'extrémité lecture)
#   5. sleep 0.2 ; rm in out  — supprimer les noms (les FDs restent valides)
#   6. Handshake TLS complète, session prête
#
# Prérequis : openssl, mkfifo (POSIX standard)
#
# Dépendances : core/log, core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_TRANSPORT_TLS:-}" ]] && return 0
readonly _ENSH_TRANSPORT_TLS=1

ensh::import core/log
ensh::import core/hex

# ── Registre des connexions TLS ───────────────────────────────────────────────
#
# Pour chaque handle "h" :
#   _TLS_FD_READ[h]  — FD de lecture (stdout de openssl, via fifo_out)
#   _TLS_FD_WRITE[h] — FD d'écriture (stdin de openssl, via fifo_in)
#   _TLS_PID[h]      — PID du processus openssl s_client
#   _TLS_HOST[h]     — hôte cible
#   _TLS_PORT[h]     — port cible

declare -gA _TLS_FD_READ=()
declare -gA _TLS_FD_WRITE=()
declare -gA _TLS_PID=()
declare -gA _TLS_HOST=()
declare -gA _TLS_PORT=()

# ── Ouverture d'une connexion TLS ─────────────────────────────────────────────

# tls::connect <host> <port> <var_handle_out> [timeout_seconds]
#
# Établit une connexion TLS/LDAPS via openssl s_client.
# La vérification du certificat serveur est désactivée (mode pentest).
tls::connect() {
    local host="$1"
    local -i port="$2"
    local -n _tls_conn_out="$3"
    local -i timeout="${4:-10}"

    if ! command -v openssl >/dev/null 2>&1; then
        log::error "tls::connect : openssl introuvable — requis pour LDAPS/TLS"
        return 1
    fi

    # ── Mise en place des FIFOs ───────────────────────────────────────────────
    # Nom distinct de toute variable du caller (évite le conflit de nameref)
    local _tls_key="${host}:${port}:$$:${RANDOM}"
    local fifo_in="/tmp/_ensh_tls_in_${RANDOM}"
    local fifo_out="/tmp/_ensh_tls_out_${RANDOM}"

    if ! mkfifo "${fifo_in}" "${fifo_out}" 2>/dev/null; then
        log::error "tls::connect : impossible de créer les FIFOs dans /tmp"
        return 1
    fi

    # Ouvrir les deux FIFOs en O_RDWR AVANT de démarrer openssl.
    # O_RDWR sur un FIFO ne bloque jamais, et fournit les deux extrémités
    # simultanément. Ceci garantit que les opens O_RDONLY et O_WRONLY
    # d'openssl ne se bloquent pas non plus.
    local -i fd_write fd_read
    exec {fd_write}<>"${fifo_in}"
    exec {fd_read}<>"${fifo_out}"

    # ── Démarrage de openssl s_client ─────────────────────────────────────────
    openssl s_client \
        -connect "${host}:${port}" \
        -quiet \
        -verify_quiet \
        2>/dev/null \
        < "${fifo_in}" \
        > "${fifo_out}" &
    local -i pid=$!

    # Laisser 200ms au sous-shell openssl pour ouvrir les FIFOs par nom,
    # puis supprimer les entrées de répertoire (les FDs restent valides).
    sleep 0.2
    rm -f "${fifo_in}" "${fifo_out}"

    # ── Attente du handshake TLS ──────────────────────────────────────────────
    # On attend 0.6s minimum (handshake réseau) puis on vérifie que le process
    # est toujours vivant. Si openssl a échoué, il aura déjà terminé.
    sleep 0.4

    if ! kill -0 "${pid}" 2>/dev/null; then
        eval "exec ${fd_write}>&-" 2>/dev/null
        eval "exec ${fd_read}<&-"  2>/dev/null
        log::error "tls::connect : openssl s_client a échoué pour ${host}:${port}"
        log::info  "  → Tenter manuellement : openssl s_client -connect ${host}:${port} 2>&1 | head -20"
        return 1
    fi

    _TLS_FD_READ["${_tls_key}"]="${fd_read}"
    _TLS_FD_WRITE["${_tls_key}"]="${fd_write}"
    _TLS_PID["${_tls_key}"]="${pid}"
    _TLS_HOST["${_tls_key}"]="${host}"
    _TLS_PORT["${_tls_key}"]="${port}"

    _tls_conn_out="${_tls_key}"
    log::info "tls : connecté à ${host}:${port} (TLS/LDAPS)"
    return 0
}

# ── Fermeture ─────────────────────────────────────────────────────────────────

# tls::close <handle>
tls::close() {
    local handle="$1"
    local pid="${_TLS_PID[${handle}]:-}"
    local fd_read="${_TLS_FD_READ[${handle}]:-}"
    local fd_write="${_TLS_FD_WRITE[${handle}]:-}"

    [[ -z "${pid}" ]] && return 0

    # Fermer l'extrémité écriture en premier : openssl reçoit EOF sur stdin
    # et ferme proprement la connexion TLS.
    [[ -n "${fd_write}" ]] && eval "exec ${fd_write}>&-" 2>/dev/null || true
    [[ -n "${fd_read}" ]]  && eval "exec ${fd_read}<&-"  2>/dev/null || true

    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true

    unset "_TLS_FD_READ[${handle}]"
    unset "_TLS_FD_WRITE[${handle}]"
    unset "_TLS_PID[${handle}]"
    unset "_TLS_HOST[${handle}]"
    unset "_TLS_PORT[${handle}]"

    log::debug "tls : connexion fermée (${handle})"
}

# ── Envoi ─────────────────────────────────────────────────────────────────────

# tls::send <handle> <hex_data>
tls::send() {
    local handle="$1"
    local hex="${2^^}"
    local fd_write="${_TLS_FD_WRITE[${handle}]:-}"

    [[ -z "${fd_write}" ]] && { log::error "tls::send : handle inconnu"; return 1; }

    log::trace "tls::send ${#hex} nibbles → ${_TLS_HOST[${handle}]}:${_TLS_PORT[${handle}]}"

    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        printf "\\x${hex:${i}:2}"
    done >&${fd_write}
}

# ── Réception ─────────────────────────────────────────────────────────────────

# tls::recv <handle> <length_bytes> <var_out> [timeout_seconds]
tls::recv() {
    local handle="$1"
    local -i length="$2"
    local -n _tls_recv_out="$3"
    local -i timeout="${4:-30}"
    local fd_read="${_TLS_FD_READ[${handle}]:-}"

    [[ -z "${fd_read}" ]] && { log::error "tls::recv : handle inconnu"; return 1; }

    if (( length == 0 )); then
        _tls_recv_out=""
        return 0
    fi

    log::trace "tls::recv ${length} octets depuis ${_TLS_HOST[${handle}]}:${_TLS_PORT[${handle}]}"

    _tls_recv_out=""
    local -i received=0
    local raw_byte

    while (( received < length )); do
        # LC_ALL=C : lecture byte-par-byte sans interprétation UTF-8
        if ! LC_ALL=C IFS= read -r -d '' -n 1 -t "${timeout}" raw_byte <&${fd_read} 2>/dev/null; then
            if (( received > 0 )); then
                log::warn "tls::recv : timeout après ${received}/${length} octets"
            else
                log::warn "tls::recv : connexion TLS fermée ou timeout"
            fi
            return 1
        fi

        if [[ -z "${raw_byte}" ]]; then
            _tls_recv_out+="00"
        else
            printf -v _tls_recv_out '%s%02X' "${_tls_recv_out}" "'${raw_byte}"
        fi
        (( received++ ))
    done

    return 0
}

# tls::recv_available <handle> <var_out> [max_bytes] [timeout_seconds]
tls::recv_available() {
    local handle="$1"
    local -n _tls_ra_out="$2"
    local -i max="${3:-65535}"
    local -i timeout="${4:-2}"
    local fd_read="${_TLS_FD_READ[${handle}]:-}"

    [[ -z "${fd_read}" ]] && { log::error "tls::recv_available : handle inconnu"; return 1; }

    _tls_ra_out=""
    local -i received=0
    local raw_byte

    while (( received < max )); do
        if ! LC_ALL=C IFS= read -r -d '' -n 1 -t "${timeout}" raw_byte <&${fd_read} 2>/dev/null; then
            break
        fi

        if [[ -z "${raw_byte}" ]]; then
            _tls_ra_out+="00"
        else
            printf -v _tls_ra_out '%s%02X' "${_tls_ra_out}" "'${raw_byte}"
        fi
        (( received++ ))
    done

    log::trace "tls::recv_available : ${received} octets reçus"
    return 0
}

# ── Utilitaires ───────────────────────────────────────────────────────────────

# tls::is_connected <handle>
tls::is_connected() {
    local handle="$1"
    [[ -n "${_TLS_PID[${handle}]:-}" ]] && kill -0 "${_TLS_PID[${handle}]}" 2>/dev/null
}
