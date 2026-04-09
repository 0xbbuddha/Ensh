#!/usr/bin/env bash
#
# lib/transport/tcp.sh — Transport TCP via /dev/tcp
#
# Fournit une abstraction pour établir des connexions TCP, envoyer et recevoir
# des données binaires (en hexadécimal) sans dépendance externe.
#
# Chaque connexion est identifiée par un "handle" : une chaîne unique qui
# référence les descripteurs de fichier ouverts sur /dev/tcp.
#
# Limites de /dev/tcp :
#   - Bash ne peut pas attendre un nombre précis d'octets de façon atomique.
#     Les lectures sont faites par blocs avec timeout.
#   - Les octets nuls (0x00) dans les données reçues sont perdus par Bash
#     lors de la lecture dans une variable. Pour contourner cela, la réception
#     est redirigée via xxd/od afin d'obtenir une représentation hex stable.
#
# Dépendances : core/log, core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_TRANSPORT_TCP:-}" ]] && return 0
readonly _ENSH_TRANSPORT_TCP=1

ensh::import core/log
ensh::import core/hex

# ── Registre des connexions ouvertes ──────────────────────────────────────────
#
# Pour chaque handle "h" :
#   _TCP_FD[h]    — descripteur de fichier bidirectionnel (<>) sur /dev/tcp
#   _TCP_HOST[h]  — hôte cible
#   _TCP_PORT[h]  — port cible
#
# Note : /dev/tcp doit être ouvert avec <> (bidirectionnel) pour une socket
# TCP full-duplex. On utilise la syntaxe {var}<> (Bash 4.1+) pour que Bash
# alloue automatiquement un FD libre, évitant tout conflit avec les FDs
# hérités de l'environnement parent.
#
declare -gA _TCP_FD=()
declare -gA _TCP_HOST=()
declare -gA _TCP_PORT=()

# ── Ouverture d'une connexion ─────────────────────────────────────────────────

# tcp::connect <host> <port> <var_handle_out> [timeout_seconds]
#
# Ouvre une connexion TCP vers <host>:<port>.
# Stocke un handle dans <var_handle_out>.
#
# Retourne 0 en cas de succès, 1 en cas d'échec.
tcp::connect() {
    local host="$1"
    local -i port="$2"
    local -n _tcp_conn_out="$3"
    local -i timeout="${4:-10}"

    local _tcp_new_handle="${host}:${port}:$$:${RANDOM}"

    # {_tcp_fd_var}<> : Bash alloue automatiquement un FD libre (Bash 4.1+).
    # Évite tout conflit avec les FDs hérités de l'environnement parent.
    #
    # ATTENTION : exec sans commande applique ses redirections de façon PERMANENTE
    # au shell courant. Si on écrit `exec {fd}<>/dev/tcp/... 2>/dev/null`, stderr
    # sera définitivement redirigé vers /dev/null pour tout le reste du processus.
    # On sauvegarde donc stderr avant l'exec et on le restaure ensuite.
    local -i _tcp_fd_var _tcp_stderr_bak
    exec {_tcp_stderr_bak}>&2   # sauvegarder stderr dans un FD libre
    exec 2>/dev/null             # silencer stderr (messages "Connection refused" de Bash)
    exec {_tcp_fd_var}<>/dev/tcp/${host}/${port}
    local -i _tcp_rc=$?
    exec 2>&${_tcp_stderr_bak}   # restaurer stderr
    exec {_tcp_stderr_bak}>&-    # fermer le FD de sauvegarde

    if (( _tcp_rc != 0 )); then
        log::error "tcp::connect : impossible de se connecter à ${host}:${port}"
        return 1
    fi

    log::debug "tcp::connect → ${host}:${port} (fd=${_tcp_fd_var})"
    _TCP_FD["${_tcp_new_handle}"]="${_tcp_fd_var}"
    _TCP_HOST["${_tcp_new_handle}"]="${host}"
    _TCP_PORT["${_tcp_new_handle}"]="${port}"

    _tcp_conn_out="${_tcp_new_handle}"
    log::info "tcp : connecté à ${host}:${port}"
    return 0
}

# ── Fermeture ─────────────────────────────────────────────────────────────────

# tcp::close <handle>
tcp::close() {
    local handle="$1"
    local fd="${_TCP_FD[${handle}]:-}"

    [[ -z "${fd}" ]] && { log::warn "tcp::close : handle inconnu"; return 1; }

    eval "exec ${fd}<&-" 2>/dev/null   # fermer le FD bidirectionnel

    unset '_TCP_FD['"${handle}"']'
    unset '_TCP_HOST['"${handle}"']'
    unset '_TCP_PORT['"${handle}"']'

    log::debug "tcp : connexion fermée (${handle})"
}

# ── Envoi ─────────────────────────────────────────────────────────────────────

# tcp::send <handle> <hex_data>
#
# Envoie des données hexadécimales sur la connexion.
# Les données sont converties en binaire avant envoi.
tcp::send() {
    local handle="$1"
    local hex="${2^^}"
    local fd="${_TCP_FD[${handle}]:-}"

    [[ -z "${fd}" ]] && { log::error "tcp::send : handle inconnu"; return 1; }

    log::trace "tcp::send ${#hex} nibbles → ${_TCP_HOST[${handle}]}:${_TCP_PORT[${handle}]}"

    # Convertir hex → binaire et écrire sur le FD bidirectionnel
    # >&N nécessite un numéro sans guillemets — les quotes empêchent la redirection FD
    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        printf "\\x${hex:${i}:2}"
    done >&${fd}
}

# ── Réception ─────────────────────────────────────────────────────────────────

# tcp::recv <handle> <length_bytes> <var_out> [timeout_seconds]
#
# Reçoit exactement <length_bytes> octets depuis la connexion.
# Le résultat est stocké en hexadécimal dans <var_out>.
#
# Retourne 0 si tous les octets ont été reçus, 1 en cas de timeout ou d'erreur.
tcp::recv() {
    local handle="$1"
    local -i length="$2"
    local -n _tcp_recv_out="$3"
    local -i timeout="${4:-30}"
    local fd="${_TCP_FD[${handle}]:-}"

    [[ -z "${fd}" ]] && { log::error "tcp::recv : handle inconnu"; return 1; }

    if (( length == 0 )); then
        _tcp_recv_out=""
        return 0
    fi

    log::trace "tcp::recv ${length} octets depuis ${_TCP_HOST[${handle}]}:${_TCP_PORT[${handle}]}"

    _tcp_recv_out=""
    local -i received=0
    local raw_byte

    while (( received < length )); do
        # LC_ALL=C : force la lecture byte par byte (pas caractère UTF-8).
        # Sans ça, en locale UTF-8, read -n 1 peut consommer plusieurs bytes
        # pour un seul "caractère" (ex: 0xDE consomme aussi le byte suivant),
        # causant une perte silencieuse de données binaires.
        if ! LC_ALL=C IFS= read -r -d '' -n 1 -t "${timeout}" raw_byte <&${fd} 2>/dev/null; then
            if (( received > 0 )); then
                log::warn "tcp::recv : timeout après ${received}/${length} octets"
            else
                log::warn "tcp::recv : connexion fermée ou timeout"
            fi
            return 1
        fi

        if [[ -z "${raw_byte}" ]]; then
            _tcp_recv_out+="00"
        else
            printf -v _tcp_recv_out '%s%02X' "${_tcp_recv_out}" "'${raw_byte}"
        fi
        (( received++ ))
    done

    return 0
}

# tcp::recv_available <handle> <var_out> [max_bytes] [timeout_seconds]
#
# Reçoit autant d'octets que disponibles (jusqu'à <max_bytes>).
tcp::recv_available() {
    local handle="$1"
    local -n _tcp_ra_out="$2"
    local -i max="${3:-65535}"
    local -i timeout="${4:-2}"
    local fd="${_TCP_FD[${handle}]:-}"

    [[ -z "${fd}" ]] && { log::error "tcp::recv_available : handle inconnu"; return 1; }

    _tcp_ra_out=""
    local -i received=0
    local raw_byte

    while (( received < max )); do
        if ! LC_ALL=C IFS= read -r -d '' -n 1 -t "${timeout}" raw_byte <&${fd} 2>/dev/null; then
            break
        fi

        if [[ -z "${raw_byte}" ]]; then
            _tcp_ra_out+="00"
        else
            printf -v _tcp_ra_out '%s%02X' "${_tcp_ra_out}" "'${raw_byte}"
        fi
        (( received++ ))
    done

    log::trace "tcp::recv_available : ${received} octets reçus"
    return 0
}

# ── Utilitaires ───────────────────────────────────────────────────────────────

# tcp::is_connected <handle>
# Retourne 0 si le handle est enregistré comme connecté.
tcp::is_connected() {
    [[ -n "${_TCP_FD[${1}]:-}" ]]
}

# tcp::info <handle>
# Affiche des informations sur une connexion (pour le débogage).
tcp::info() {
    local handle="$1"
    if tcp::is_connected "${handle}"; then
        log::debug "tcp::info : ${_TCP_HOST[${handle}]}:${_TCP_PORT[${handle}]} fd=${_TCP_FD[${handle}]}"
    else
        log::debug "tcp::info : handle inconnu ou fermé"
    fi
}
