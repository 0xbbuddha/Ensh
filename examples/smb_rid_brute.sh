#!/usr/bin/env bash
#
# examples/smb_rid_brute.sh — RID brute via LSARPC / LookupSids
#
# Reconstitue les SID d'un domaine à partir de son SID de base puis résout
# chaque RID via LsarLookupSids. Fonctionne sur SMB2 uniquement.
#
# Usage :
#   bash examples/smb_rid_brute.sh [options] <host> <domain> <user> <password> <max_rid>
#
# Options :
#   -p, --port <port>   Port SMB (défaut : 445)
#   -t, --timeout <s>   Timeout réseau en secondes (défaut : 10)
#   -b, --batch <n>     Taille de batch LookupSids (défaut : 64)
#
# Exemples :
#   bash examples/smb_rid_brute.sh 10.10.10.1 corp.local administrator 'P@ssw0rd' 5000
#   bash examples/smb_rid_brute.sh -b 128 10.10.10.1 corp.local admin pass 2000
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/msrpc/lsarpc

PORT=445
TIMEOUT=10
BATCH_SIZE=64

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)    PORT="$2";       shift 2 ;;
        -t|--timeout) TIMEOUT="$2";    shift 2 ;;
        -b|--batch)   BATCH_SIZE="$2"; shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

HOST="${_args[0]:-}"
DOMAIN="${_args[1]:-}"
USER="${_args[2]:-}"
PASS="${_args[3]:-}"
MAX_RID="${_args[4]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" || -z "${MAX_RID}" ]]; then
    printf 'Usage : %s [options] <host> <domain> <user> <password> <max_rid>\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -p <port>    Port SMB (défaut : 445)\n' >&2
    printf '  -t <sec>     Timeout en secondes\n' >&2
    printf '  -b <n>       Taille de batch LookupSids (défaut : 64)\n' >&2
    exit 1
fi

if [[ ! "${MAX_RID}" =~ ^[0-9]+$ ]]; then
    printf 'Erreur : <max_rid> doit être un entier positif.\n' >&2
    exit 1
fi

if [[ ! "${BATCH_SIZE}" =~ ^[0-9]+$ ]] || (( BATCH_SIZE < 1 )); then
    printf 'Erreur : --batch doit être un entier strictement positif.\n' >&2
    exit 1
fi

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — RID Brute SMB / LSARPC\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible    : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine  : %s\n' "${DOMAIN}"
    printf  '  Compte   : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '  Max RID  : %s\n' "${MAX_RID}"
    printf  '  Batch    : %s\n' "${BATCH_SIZE}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }
_warn() { printf ' \033[33m[!]\033[0m %s\n' "$*"; }

_cleanup() {
    [[ -n "${policy_handle:-}" ]] && lsarpc::close_handle "${sess}" "${file_id}" "${policy_handle}" >/dev/null 2>&1 || true
    [[ -n "${file_id:-}" ]] && smb::session::close_pipe "${sess}" "${file_id}" >/dev/null 2>&1 || true
    [[ -n "${sess:-}" ]] && smb::session::disconnect "${sess}" >/dev/null 2>&1 || true
}

_banner

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

_info "Authentification NTLMv2 (${DOMAIN}\\${USER})..."
if ! smb::session::login "${sess}" "${USER}" "${DOMAIN}" "${PASS}"; then
    _err "Authentification échouée — vérifier les credentials"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Authentifié."

_info "Ouverture du pipe \\\\lsarpc sur IPC\$..."
declare file_id
if ! smb::session::open_pipe "${sess}" "\\lsarpc" file_id; then
    _err "Impossible d'ouvrir le pipe \\lsarpc — accès refusé ?"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Pipe ouvert."

_info "DCE/RPC BIND (LSARPC)..."
if ! lsarpc::bind "${sess}" "${file_id}"; then
    _err "BIND LSARPC échoué"
    _cleanup
    exit 1
fi
_ok "BIND OK."

_info "LsarOpenPolicy2..."
declare policy_handle
if ! lsarpc::open_policy "${sess}" "${file_id}" policy_handle; then
    _err "LsarOpenPolicy2 échoué"
    _cleanup
    exit 1
fi
_ok "Handle policy obtenu."

_info "QueryInformationPolicy2(DomainDns)..."
declare -A policy_info=()
if ! lsarpc::query_info_policy "${sess}" "${file_id}" "${policy_handle}" "${LSARPC_POLICY_INFO_DOMAIN_DNS}" policy_info; then
    _err "LsarQueryInformationPolicy2(DomainDns) échoué"
    _cleanup
    exit 1
fi
_ok "SID domaine : ${policy_info[domain_sid]}"

printf '\n'
_info "RID brute 0..${MAX_RID} via LsarLookupSids..."
printf '\n'

declare -a hits=()
declare -i batch_start=0
declare -i max_rid_int="${MAX_RID}"

while (( batch_start <= max_rid_int )); do
    declare -i batch_end=$(( batch_start + BATCH_SIZE - 1 ))
    (( batch_end > max_rid_int )) && batch_end="${max_rid_int}"

    declare -a sids=()
    declare -i rid
    for (( rid = batch_start; rid <= batch_end; rid++ )); do
        sid_hex=""
        lsarpc::sid::append_rid "${policy_info[domain_sid]}" "${rid}" sid_hex
        sids+=("${sid_hex}")
    done

    declare -a names=()
    if ! lsarpc::lookup_sids "${sess}" "${file_id}" "${policy_handle}" sids names; then
        if (( BATCH_SIZE > 1 )); then
            BATCH_SIZE=$(( BATCH_SIZE / 2 ))
            (( BATCH_SIZE < 1 )) && BATCH_SIZE=1
            _warn "Batch réduit à ${BATCH_SIZE} après échec RPC sur ${batch_start}-${batch_end}"
            continue
        fi

        _err "LsarLookupSids échoué sur le RID ${batch_start}"
        _cleanup
        exit 1
    fi

    declare -i expected_count=$(( batch_end - batch_start + 1 ))
    while (( ${#names[@]} < expected_count )); do
        names+=("unknown::")
    done

    declare -i idx=0
    for (( rid = batch_start; rid <= batch_end; rid++ )); do
        IFS=':' read -r sid_type sid_domain sid_name <<< "${names[idx]}"
        (( idx++ ))

        if [[ -z "${sid_name}" || "${sid_type}" == "unknown" || "${sid_type}" == "invalid" ]]; then
            continue
        fi

        identity="${sid_name}"
        [[ -n "${sid_domain}" ]] && identity="${sid_domain}\\${sid_name}"
        hits+=("${rid}:${sid_type}:${identity}")
    done

    batch_start=$(( batch_end + 1 ))
done

printf ' %-8s  %-18s  %s\n' "RID" "TYPE" "IDENTITÉ"
printf ' %s\n' "────────────────────────────────────────────────────────────────"

for entry in "${hits[@]}"; do
    IFS=':' read -r rid sid_type identity <<< "${entry}"
    printf ' \033[32m%-8s\033[0m  %-18s  %s\n' "${rid}" "${sid_type}" "${identity}"
done

printf '\n %s\n' "────────────────────────────────────────────────────────────────"
printf ' %d entrée(s) résolue(s) dans %s\n\n' "${#hits[@]}" "${policy_info[name]}"

_cleanup
