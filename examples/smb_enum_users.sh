#!/usr/bin/env bash
#
# examples/smb_enum_users.sh — Énumération des utilisateurs d'un domaine via SAMR
#
# Récupère la liste des comptes utilisateurs (USER_NORMAL_ACCOUNT) via
# SamrEnumerateUsersInDomain (DCE/RPC over SMB2). Fonctionne sur SMB2 uniquement.
#
# Usage :
#   bash examples/smb_enum_users.sh [options] <host> <domain> <user> <password>
#
# Options :
#   -p, --port <port>  Port SMB (défaut : 445)
#   -t, --timeout <s>  Timeout réseau en secondes (défaut : 10)
#
# Exemples :
#   bash examples/smb_enum_users.sh 10.10.10.1 corp.local administrator 'P@ssw0rd'
#   bash examples/smb_enum_users.sh -p 445 -t 15 192.168.1.10 WORKGROUP admin pass
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/msrpc/samr

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
    printf  ' Ensh — Énumération SAMR / Utilisateurs domaine\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible   : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine : %s\n'    "${DOMAIN}"
    printf  '  Compte  : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }

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

# ── Ouverture du pipe \samr ───────────────────────────────────────────────────

_info "Ouverture du pipe \\\\samr sur IPC\$..."
declare file_id
if ! smb::session::open_pipe "${sess}" "\\samr" file_id; then
    _err "Impossible d'ouvrir le pipe \\samr — accès refusé ?"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Pipe ouvert."

_info "DCE/RPC BIND (SAMR)..."
if ! samr::bind "${sess}" "${file_id}"; then
    _err "BIND SAMR échoué"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "BIND OK."

# ── SamrConnect ───────────────────────────────────────────────────────────────

_info "SamrConnect..."
declare server_handle
if ! samr::connect "${sess}" "${file_id}" server_handle; then
    _err "SamrConnect échoué"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Handle serveur SAM obtenu."

# ── SamrLookupDomainInSamServer ───────────────────────────────────────────────

# Utiliser la partie "NetBIOS" du domaine (avant le premier point)
DOMAIN_SHORT="${DOMAIN%%.*}"

_info "Lookup SID du domaine '${DOMAIN_SHORT}'..."
declare domain_sid
if ! samr::lookup_domain "${sess}" "${file_id}" "${server_handle}" "${DOMAIN_SHORT}" domain_sid; then
    _err "SamrLookupDomainInSamServer échoué pour '${DOMAIN_SHORT}'"
    samr::close_handle "${sess}" "${file_id}" "${server_handle}"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "SID domaine : ${domain_sid}"

# ── SamrOpenDomain ────────────────────────────────────────────────────────────

_info "SamrOpenDomain..."
declare domain_handle
if ! samr::open_domain "${sess}" "${file_id}" "${server_handle}" "${domain_sid}" domain_handle; then
    _err "SamrOpenDomain échoué"
    samr::close_handle "${sess}" "${file_id}" "${server_handle}"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Handle domaine obtenu."

# ── SamrEnumerateUsersInDomain ────────────────────────────────────────────────

printf '\n'
_info "Énumération des utilisateurs (USER_NORMAL_ACCOUNT)..."
printf '\n'

declare -a users=()
if ! samr::enumerate_users "${sess}" "${file_id}" "${domain_handle}" users; then
    _err "SamrEnumerateUsersInDomain échoué"
    samr::close_handle "${sess}" "${file_id}" "${domain_handle}"
    samr::close_handle "${sess}" "${file_id}" "${server_handle}"
    smb::session::close_pipe "${sess}" "${file_id}"
    smb::session::disconnect "${sess}"
    exit 1
fi

# ── Affichage des résultats ───────────────────────────────────────────────────

declare -i total="${#users[@]}"

printf ' %-8s  %s\n' "RID" "NOM"
printf ' %s\n' "──────────────────────────────────────"

for entry in "${users[@]}"; do
    IFS=':' read -r rid name <<< "${entry}"
    printf ' \033[32m%-8s\033[0m  %s\n' "${rid}" "${name}"
done

printf '\n %s\n' "──────────────────────────────────────"
printf ' %d compte(s) trouvé(s) dans %s\n\n' "${total}" "${DOMAIN_SHORT}"

# ── Nettoyage ─────────────────────────────────────────────────────────────────

samr::close_handle "${sess}" "${file_id}" "${domain_handle}"
samr::close_handle "${sess}" "${file_id}" "${server_handle}"
smb::session::close_pipe "${sess}" "${file_id}"
smb::session::disconnect "${sess}"
