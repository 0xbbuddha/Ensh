#!/usr/bin/env bash
#
# lib/core/log.sh — Journalisation structurée
#
# Niveaux disponibles (du moins verbeux au plus verbeux) :
#   ERROR WARN INFO DEBUG TRACE
#
# Configuration :
#   ENSH_LOG_LEVEL  — Niveau minimum affiché (défaut : INFO)
#   ENSH_LOG_COLOR  — Désactiver les couleurs si "0" (défaut : 1)
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CORE_LOG:-}" ]] && return 0
readonly _ENSH_CORE_LOG=1

# ── Niveaux et leurs priorités numériques ─────────────────────────────────────
declare -grA _LOG_PRIORITY=(
    [TRACE]=0
    [DEBUG]=1
    [INFO]=2
    [WARN]=3
    [ERROR]=4
    [SILENT]=99
)

# ── Couleurs ANSI ─────────────────────────────────────────────────────────────
declare -gr _LOG_COLOR_RESET='\033[0m'
declare -grA _LOG_COLOR=(
    [TRACE]='\033[0;37m'      # gris clair
    [DEBUG]='\033[0;36m'      # cyan
    [INFO]='\033[0;32m'       # vert
    [WARN]='\033[0;33m'       # jaune
    [ERROR]='\033[0;31m'      # rouge
)
declare -grA _LOG_LABEL=(
    [TRACE]='TRC'
    [DEBUG]='DBG'
    [INFO]='INF'
    [WARN]='WRN'
    [ERROR]='ERR'
)

# Niveau actif (modifiable par l'utilisateur)
ENSH_LOG_LEVEL="${ENSH_LOG_LEVEL:-INFO}"
ENSH_LOG_COLOR="${ENSH_LOG_COLOR:-1}"

# ── Fonction centrale ─────────────────────────────────────────────────────────
#
# _log::write <LEVEL> <message>
#
# Fonction interne — utiliser les fonctions publiques ci-dessous.
#
_log::write() {
    local level="$1"
    shift
    local message="$*"

    # Comparer la priorité du niveau demandé avec le niveau actif
    local prio_msg="${_LOG_PRIORITY[${level}]:-2}"
    local prio_cur="${_LOG_PRIORITY[${ENSH_LOG_LEVEL}]:-2}"
    (( prio_msg < prio_cur )) && return 0

    local timestamp
    timestamp="$(date '+%H:%M:%S')"
    local label="${_LOG_LABEL[${level}]:-???}"

    if [[ "${ENSH_LOG_COLOR}" != "0" ]] && [[ -t 2 ]]; then
        local color="${_LOG_COLOR[${level}]:-}"
        printf "${color}[%s][%s] %s${_LOG_COLOR_RESET}\n" \
            "${timestamp}" "${label}" "${message}" >&2
    else
        printf '[%s][%s] %s\n' "${timestamp}" "${label}" "${message}" >&2
    fi
}

# ── API publique ──────────────────────────────────────────────────────────────

log::error() { _log::write ERROR "$@"; }
log::warn()  { _log::write WARN  "$@"; }
log::info()  { _log::write INFO  "$@"; }
log::debug() { _log::write DEBUG "$@"; }
log::trace() { _log::write TRACE "$@"; }

# log::die <message> [code_de_sortie]
# Affiche une erreur fatale et quitte le script.
log::die() {
    log::error "$1"
    exit "${2:-1}"
}

# log::hexdump <label> <hex_string>
# Affiche un dump hexadécimal lisible pour le débogage des trames réseau.
log::hexdump() {
    local label="$1"
    local hex="${2^^}"  # forcer en majuscules
    local -i offset=0
    local chunk

    _log::write DEBUG "── ${label} (${#hex} nibbles / $(( ${#hex} / 2 )) octets)"

    while [[ -n "${hex}" ]]; do
        chunk="${hex:0:32}"      # 16 octets par ligne
        hex="${hex:32}"

        # Représentation hexadécimale espacée
        local spaced=""
        local i
        for (( i=0; i<${#chunk}; i+=2 )); do
            spaced+="${chunk:${i}:2} "
        done

        # Représentation ASCII (caractères imprimables uniquement)
        local ascii=""
        for (( i=0; i<${#chunk}; i+=2 )); do
            local byte=$(( 16#${chunk:${i}:2} ))
            if (( byte >= 32 && byte < 127 )); then
                printf -v char '\\x%02x' "${byte}"
                ascii+="$(printf "${char}")"
            else
                ascii+='.'
            fi
        done

        _log::write DEBUG "$(printf '%04x' ${offset})  %-48s  %s" \
            "${spaced}" "${ascii}"
        (( offset += 16 ))
    done
}
