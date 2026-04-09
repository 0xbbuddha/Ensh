#!/usr/bin/env bash
#
# examples/smb_enum_shares.sh — Énumération de partages SMB1 via Ensh
#
# Usage :
#   bash examples/smb_enum_shares.sh [options] <host> <domain> <user> <password>
#
# Options :
#   -p, --port <port>  Port SMB (défaut : 445)
#   -t, --timeout <s>  Timeout réseau en secondes (défaut : 10)
#   -s, --shares <lst> Liste de partages à tester, séparés par des virgules
#                      (défaut : liste prédéfinie de partages communs)
#
# Exemples :
#   bash examples/smb_enum_shares.sh 10.10.10.1 corp.local administrator 'P@ssw0rd'
#   bash examples/smb_enum_shares.sh --shares "C$,ADMIN$,IPC$,sysvol" 10.10.10.1 corp admin pw
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session

# ── Parsing des arguments ─────────────────────────────────────────────────────

PORT=445
TIMEOUT=10
CUSTOM_SHARES=""

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)    PORT="$2";   shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -s|--shares)  CUSTOM_SHARES="$2"; shift 2 ;;
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
    printf '  -s <shares>  Liste de partages (ex: "C$,ADMIN$,IPC$")\n' >&2
    exit 1
fi

# ── Partages à tester ─────────────────────────────────────────────────────────

if [[ -n "${CUSTOM_SHARES}" ]]; then
    IFS=',' read -ra SHARES <<< "${CUSTOM_SHARES}"
else
    # Liste typique pour un AD Windows
    SHARES=(
        "IPC$"
        "C$"
        "ADMIN$"
        "SYSVOL"
        "NETLOGON"
        "print$"
        "Users"
        "Shares"
        "Data"
        "Backup"
        "Public"
        "Transfer"
        "IT"
        "Finance"
        "HR"
    )
fi

# ── Helpers affichage ─────────────────────────────────────────────────────────

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — Énumération SMB1 / Partages réseaux\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible   : %s\n'   "${HOST}"
    printf  '  Port    : %s\n'   "${PORT}"
    printf  '  Domaine : %s\n'   "${DOMAIN}"
    printf  '  Compte  : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '  Partages: %d à tester\n' "${#SHARES[@]}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }
_warn() { printf ' \033[33m[!]\033[0m %s\n' "$*"; }

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
    _err "Négociation SMB échouée — serveur incompatible ?"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Négociation OK."

# ── Authentification ──────────────────────────────────────────────────────────

_info "Authentification NTLMv2 (${DOMAIN}\\${USER})..."
if ! smb::session::login "${sess}" "${USER}" "${DOMAIN}" "${PASS}"; then
    _err "Authentification échouée — vérifier les credentials"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Authentifié.\n"

# ── Énumération des partages ──────────────────────────────────────────────────

printf ' %-25s  %s\n' "PARTAGE" "STATUT"
printf ' %s\n' "─────────────────────────────────────────────"

declare -a accessible=()
declare -a denied=()
declare -a not_found=()

for share in "${SHARES[@]}"; do
    declare result
    smb::session::try_share "${sess}" "${share}" result

    case "${result}" in
        "OK")
            printf ' \033[32m%-25s  ✓ ACCESSIBLE\033[0m\n' "${share}"
            accessible+=("${share}")
            ;;
        "ACCESS_DENIED")
            printf ' \033[33m%-25s  ✗ Accès refusé\033[0m\n' "${share}"
            denied+=("${share}")
            ;;
        "NOT_FOUND")
            printf ' \033[90m%-25s  — Inexistant\033[0m\n' "${share}"
            not_found+=("${share}")
            ;;
        *)
            printf ' \033[31m%-25s  ! %s\033[0m\n' "${share}" "${result}"
            ;;
    esac
done

# ── Résumé ────────────────────────────────────────────────────────────────────

printf '\n %s\n' "─────────────────────────────────────────────"
printf ' Résumé : %d accessible(s), %d refusé(s), %d inexistant(s)\n' \
    "${#accessible[@]}" "${#denied[@]}" "${#not_found[@]}"

if (( ${#accessible[@]} > 0 )); then
    printf '\n'
    _ok "Partages accessibles :"
    for s in "${accessible[@]}"; do
        printf '     \\\\%s\\%s\n' "${HOST}" "${s}"
    done
fi

if (( ${#denied[@]} > 0 )); then
    printf '\n'
    _warn "Partages existants mais accès refusé (utilisateur non admin) :"
    for s in "${denied[@]}"; do
        printf '     \\\\%s\\%s\n' "${HOST}" "${s}"
    done
fi

printf '\n'

# ── Nettoyage ─────────────────────────────────────────────────────────────────

smb::session::disconnect "${sess}"
