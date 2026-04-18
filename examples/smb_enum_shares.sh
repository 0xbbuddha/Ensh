#!/usr/bin/env bash
#
# examples/smb_enum_shares.sh — Énumération de partages SMB via Ensh
#
# Détecte les partages réels du serveur via SRVSVC / NetrShareEnum (DCE/RPC),
# sans liste prédéfinie. Fonctionne sur SMB2 uniquement.
#
# Usage :
#   bash examples/smb_enum_shares.sh [options] <host> <domain> <user> <password>
#
# Options :
#   -p, --port <port>  Port SMB (défaut : 445)
#   -t, --timeout <s>  Timeout réseau en secondes (défaut : 10)
#
# Exemples :
#   bash examples/smb_enum_shares.sh 10.10.10.1 corp.local administrator 'P@ssw0rd'
#   bash examples/smb_enum_shares.sh -p 445 -t 15 10.10.10.1 corp admin pw
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/msrpc/srvsvc

# ── Parsing des arguments ─────────────────────────────────────────────────────

PORT=445
TIMEOUT=10

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)    PORT="$2";    shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

HOST="${_args[0]:-}"
DOMAIN="${_args[1]:-}"
USER="${_args[2]:-}"
PASS="${_args[3]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" ]]; then
    printf 'Usage : %s [options] <host> <domain> <user> <password>\n' "$0" >&2
    printf '\nOptions :\n'  >&2
    printf '  -p <port>    Port SMB (défaut : 445)\n' >&2
    printf '  -t <sec>     Timeout en secondes\n' >&2
    exit 1
fi

# ── Helpers affichage ─────────────────────────────────────────────────────────

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — Énumération SMB / Partages réseaux\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible   : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine : %s\n'    "${DOMAIN}"
    printf  '  Compte  : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }
_warn() { printf ' \033[33m[!]\033[0m %s\n' "$*"; }

_share_type_str() {
    local -i t="$1"
    local base=$(( t & 0x0FFFFFFF ))
    local special=$(( t & 0x80000000 ))
    local label
    case "${base}" in
        0) label="Disk" ;;
        1) label="Print" ;;
        2) label="Device" ;;
        3) label="IPC" ;;
        *) label="?(${base})" ;;
    esac
    (( special )) && label+=" [caché]"
    printf '%s' "${label}"
}

_banner

# ── Connexion et négociation ──────────────────────────────────────────────────

_info "Connexion à ${HOST}:${PORT}..."
declare sess
if ! smb::session::connect sess "${HOST}" "${PORT}" "${TIMEOUT}"; then
    _err "Connexion TCP échouée sur ${HOST}:${PORT}"
    exit 1
fi
_ok "Connecté."

_info "Négociation SMB..."
if ! smb::session::negotiate "${sess}"; then
    _err "Négociation SMB échouée"
    smb::session::disconnect "${sess}"
    exit 1
fi

if [[ "${_SMB_VERSION[${sess}]}" != "2" ]]; then
    _err "Ce script requiert SMB2 (serveur SMB1 détecté)"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "SMB2 négocié."

# ── Authentification ──────────────────────────────────────────────────────────

_info "Authentification NTLMv2 (${DOMAIN}\\${USER})..."
if ! smb::session::login "${sess}" "${USER}" "${DOMAIN}" "${PASS}"; then
    _err "Authentification échouée — vérifier les credentials"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Authentifié."

# ── Énumération via SRVSVC ────────────────────────────────────────────────────

_info "Ouverture du pipe \\\\srvsvc sur IPC\$..."
declare file_id
if ! smb::session::open_pipe "${sess}" "\\srvsvc" file_id; then
    _err "Impossible d'ouvrir le pipe \\srvsvc — accès refusé ?"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Pipe ouvert."

_info "DCE/RPC BIND (SRVSVC)..."
if ! srvsvc::bind "${sess}" "${file_id}"; then
    _err "BIND SRVSVC échoué"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "BIND OK."
printf '\n'

_info "NetrShareEnum en cours..."
declare -a shares=()
declare _srv_enum
# Même nom que pour le TREE_CONNECT IPC$ (NetBIOS si le serveur l’exige)
_srv_enum="${HOST}"
[[ -n "${_SMB_NETR_ENUM_NAME[${sess}]:-}" ]] && _srv_enum="${_SMB_NETR_ENUM_NAME[${sess}]}"
if ! srvsvc::net_share_enum "${sess}" "${file_id}" "${_srv_enum}" shares; then
    _err "NetrShareEnum échoué"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi

# ── Affichage des résultats ───────────────────────────────────────────────────

declare -i total="${#shares[@]}"
printf ' %-25s  %-12s  %s\n' "PARTAGE" "TYPE" "COMMENTAIRE"
printf ' %s\n' "─────────────────────────────────────────────────────────"

declare -a disk_shares=()
declare -a ipc_shares=()
declare -a other_shares=()

for entry in "${shares[@]}"; do
    IFS=':' read -r name type_int comment <<< "${entry}"
    type_str="$(_share_type_str "${type_int}")"
    base_type=$(( type_int & 0x0FFFFFFF ))

    printf ' \033[32m%-25s\033[0m  %-12s  %s\n' "${name}" "${type_str}" "${comment}"

    case "${base_type}" in
        0) disk_shares+=("${name}") ;;
        3) ipc_shares+=("${name}") ;;
        *) other_shares+=("${name}") ;;
    esac
done

# ── Résumé ────────────────────────────────────────────────────────────────────

printf '\n %s\n' "─────────────────────────────────────────────────────────"
printf ' %d partage(s) détecté(s) via NetrShareEnum\n' "${total}"

if (( ${#disk_shares[@]} > 0 )); then
    printf '\n'
    _ok "Partages disque :"
    for s in "${disk_shares[@]}"; do
        printf '     \\\\%s\\%s\n' "${HOST}" "${s}"
    done
fi

# ── Nettoyage ─────────────────────────────────────────────────────────────────

smb::session::close_pipe "${sess}" "${file_id}"
smb::session::disconnect "${sess}"
printf '\n'
