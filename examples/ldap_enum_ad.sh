#!/usr/bin/env bash
#
# examples/ldap_enum_ad.sh — Énumération Active Directory via LDAP / LDAPS
#
# Usage :
#   bash examples/ldap_enum_ad.sh [--ldaps] <host> <domain> <user> <password>
#
# Options :
#   -s, --ldaps   Utiliser LDAPS (TLS sur port 636) — nécessite openssl
#
# Exemple :
#   bash examples/ldap_enum_ad.sh 10.10.10.1 corp.local admin 'P@ssw0rd'
#   bash examples/ldap_enum_ad.sh --ldaps 10.10.10.1 corp.local admin 'P@ssw0rd'
#
# ─────────────────────────────────────────────────────────────────────────────

ENSH_LOG_LEVEL="${ENSH_LOG_LEVEL:-WARN}"
source "$(dirname "${BASH_SOURCE[0]}")/../ensh.sh"

ensh::import protocol/ldap/session
ensh::import protocol/ldap/filter
ensh::import protocol/ldap/search

# ── Parsing des arguments ─────────────────────────────────────────────────────

USE_TLS=0

_args=()
for _arg in "$@"; do
    case "${_arg}" in
        -s|--ldaps|--tls) USE_TLS=1 ;;
        *) _args+=("${_arg}") ;;
    esac
done

HOST="${_args[0]:-}"
DOMAIN="${_args[1]:-}"
USER="${_args[2]:-}"
PASS="${_args[3]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" ]]; then
    printf 'Usage : %s [--ldaps] <host> <domain> <user> <password>\n' "$0" >&2
    printf '\n  --ldaps    LDAPS/TLS sur port 636 (requis si le serveur exige le signing)\n' >&2
    exit 1
fi

# Construire la base DN depuis le FQDN du domaine : corp.local → dc=corp,dc=local
BASE_DN=""
IFS='.' read -ra _parts <<< "${DOMAIN}"
for _part in "${_parts[@]}"; do
    BASE_DN+="dc=${_part},"
done
BASE_DN="${BASE_DN%,}"

# Format UPN pour le bind : user@domain
BIND_DN="${USER}@${DOMAIN}"

# ── Helpers d'affichage ───────────────────────────────────────────────────────

_banner() { printf '\033[1m%s\033[0m\n' "$*"; }
_ok()     { printf '[\033[0;32m+\033[0m] %s\n' "$*"; }
_info()   { printf '[\033[0;36m*\033[0m] %s\n' "$*"; }
_warn()   { printf '[\033[0;33m!\033[0m] %s\n' "$*"; }
_err()    { printf '[\033[0;31m✗\033[0m] %s\n' "$*"; }
_item()   { printf '  %-30s' "$1"; shift; printf ' %s' "$@"; printf '\n'; }

# ── Connexion & authentification ──────────────────────────────────────────────

_banner "══════════════════════════════════════════════"
_banner " Ensh — Énumération LDAP / Active Directory  "
_banner "══════════════════════════════════════════════"
printf '  Cible   : %s\n' "${HOST}"
printf '  Domaine : %s\n' "${DOMAIN}"
printf '  BaseDN  : %s\n' "${BASE_DN}"
printf '  Compte  : %s\n' "${BIND_DN}"
if (( USE_TLS )); then
    printf '  Mode    : \033[0;32mLDAPS (TLS port 636)\033[0m\n\n'
else
    printf '  Mode    : LDAP (port 389)\n\n'
fi

declare session
if (( USE_TLS )); then
    _info "Connexion TLS à ${HOST}:636..."
    if ! ldap::session::connect_tls session "${HOST}" 636 10; then
        _err "Connexion LDAPS échouée sur ${HOST}:636 — openssl disponible ?"
        exit 1
    fi
else
    _info "Connexion à ${HOST}:389..."
    if ! ldap::session::connect session "${HOST}" 389 10; then
        _err "Connexion TCP échouée sur ${HOST}:389"
        exit 1
    fi
fi
_ok "Connecté."

_info "Authentification LDAP (simple bind)..."
if ! ldap::session::bind_simple "${session}" "${BIND_DN}" "${PASS}"; then
    if (( ! USE_TLS )); then
        _err "Authentification échouée — si le serveur exige le signing, relancer avec --ldaps"
    else
        _err "Authentification échouée — vérifier les credentials ou essayer avec le DN complet"
    fi
    ldap::session::disconnect "${session}"
    exit 1
fi
_ok "Authentifié en tant que ${BIND_DN}"
printf '\n'

# ── Section 1 : Utilisateurs ──────────────────────────────────────────────────

_banner "[1/4] Comptes utilisateurs"
printf '──────────────────────────────────────────\n'

declare _filt_user _filt_sam _filt_users
ldap::filter::equal "objectClass" "user" _filt_user
ldap::filter::present "sAMAccountName" _filt_sam
ldap::filter::and _filt_users "${_filt_user}" "${_filt_sam}"

ldap::session::search "${session}" u_res "${BASE_DN}" "${LDAP_SCOPE_SUB}" \
    "${_filt_users}" \
    "sAMAccountName" "displayName" "description" "userAccountControl" "adminCount"

declare -i u_count="${u_res_count:-0}"
printf '  → \033[1m%d\033[0m compte(s) trouvé(s)\n\n' "${u_count}"

declare -i i
for (( i=0; i<u_count; i++ )); do
    declare -n _uent="u_res_${i}"
    declare _sam="${_uent[attr:sAMAccountName]:-?}"
    declare _display="${_uent[attr:displayName]:-}"
    declare _desc="${_uent[attr:description]:-}"
    declare _uac="${_uent[attr:userAccountControl]:-0}"
    declare _admin="${_uent[attr:adminCount]:-0}"

    declare _status="\033[0;32m●\033[0m"
    (( _uac & 2 )) && _status="\033[0;90m○\033[0m"   # désactivé

    declare _flags=""
    (( _uac & 0x10000 )) && _flags+=" \033[0;33m[PASS_NEVER_EXP]\033[0m"
    (( _uac & 0x400000 )) && _flags+=" \033[0;31m[NO_PREAUTH]\033[0m"
    [[ "${_admin}" == "1" ]] && _flags+=" \033[0;31m[ADMIN]\033[0m"

    printf '  %b %-22s' "${_status}" "${_sam}"
    [[ -n "${_display}" && "${_display}" != "${_sam}" ]] && printf '  (%s)' "${_display}"
    printf '%b' "${_flags}"
    [[ -n "${_desc}" ]] && printf '\n    └─ %s' "${_desc}"
    printf '\n'
done

# ── Section 2 : Comptes SPN (Kerberoasting) ───────────────────────────────────

printf '\n'
_banner "[2/4] Comptes avec SPN (Kerberoasting)"
printf '──────────────────────────────────────────\n'

ldap::session::get_spn_accounts "${session}" spn_res "${BASE_DN}"

declare -i spn_count="${spn_res_count:-0}"
if (( spn_count == 0 )); then
    printf '  Aucun compte avec SPN.\n'
else
    printf '  → \033[1;31m%d\033[0m compte(s) kerberoastable(s) !\n\n' "${spn_count}"
    for (( i=0; i<spn_count; i++ )); do
        declare -n _sent="spn_res_${i}"
        printf '  \033[0;31m[SPN]\033[0m \033[1m%s\033[0m\n' "${_sent[attr:sAMAccountName]:-}"
        if [[ -n "${_sent[attr:servicePrincipalName]:-}" ]]; then
            while IFS= read -r _spn_line; do
                [[ -n "${_spn_line}" ]] && printf '         └─ %s\n' "${_spn_line}"
            done <<< "${_sent[attr:servicePrincipalName]}"
        fi
    done
fi

# ── Section 3 : Groupes ───────────────────────────────────────────────────────

printf '\n'
_banner "[3/4] Groupes du domaine"
printf '──────────────────────────────────────────\n'

declare _filt_grp
ldap::filter::ad_groups _filt_grp
ldap::session::search "${session}" grp_res "${BASE_DN}" "${LDAP_SCOPE_SUB}" \
    "${_filt_grp}" "cn" "description" "member"

declare -i grp_count="${grp_res_count:-0}"
printf '  → \033[1m%d\033[0m groupe(s) trouvé(s)\n\n' "${grp_count}"

    for (( i=0; i<grp_count; i++ )); do
    declare -n _gent="grp_res_${i}"
    declare _gcn="${_gent[attr:cn]:-}"
    declare _gdesc="${_gent[attr:description]:-}"
    declare _gmembers="${_gent[attr:member]:-}"
    declare -i _member_count=0
    [[ -n "${_gmembers}" ]] && _member_count=$(printf '%s\n' "${_gmembers}" | grep -c .)

    # Mettre en évidence les groupes à privilèges
    declare _highlight=""
    case "${_gcn}" in
        "Domain Admins"|"Enterprise Admins"|"Schema Admins"|"Administrators")
            _highlight="\033[0;31m" ;;
        "Domain Users"|"Domain Computers"|"Domain Controllers")
            _highlight="\033[0;36m" ;;
    esac

    printf '  %b%-35s\033[0m  %2d membre(s)' "${_highlight}" "${_gcn}" "${_member_count}"
    [[ -n "${_gdesc}" ]] && printf '  — %s' "${_gdesc}"
    printf '\n'

    # Afficher les membres des groupes à privilèges
    if [[ -n "${_highlight}" ]] && [[ "${_highlight}" == *"31m"* ]] && [[ -n "${_gmembers}" ]]; then
        while IFS= read -r _mbr; do
            [[ -n "${_mbr}" ]] && printf '    └─ %s\n' "${_mbr}"
        done <<< "${_gmembers}"
    fi
done

# ── Section 4 : Machines ──────────────────────────────────────────────────────

printf '\n'
_banner "[4/4] Ordinateurs du domaine"
printf '──────────────────────────────────────────\n'

ldap::session::get_computers "${session}" cmp_res "${BASE_DN}"

declare -i cmp_count="${cmp_res_count:-0}"
printf '  → \033[1m%d\033[0m ordinateur(s)\n\n' "${cmp_count}"

for (( i=0; i<cmp_count; i++ )); do
    declare -n _cent="cmp_res_${i}"
    printf '  %-25s  %-30s  %s\n' \
        "${_cent[attr:cn]:-}" \
        "${_cent[attr:dNSHostName]:-}" \
        "${_cent[attr:operatingSystem]:-}"
done

# ── Fin ───────────────────────────────────────────────────────────────────────

printf '\n'
_banner "══════════════════════════════════════════════"
ldap::session::disconnect "${session}"
_ok "Session LDAP fermée."
