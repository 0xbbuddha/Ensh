#!/usr/bin/env bash
#
# examples/smb_list_dir.sh -- Listing de répertoire via SMB2 QUERY_DIRECTORY
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/smb/smb2/create
ensh::import protocol/smb/smb2/query_directory
ensh::import protocol/smb/smb2/close

PORT=445
TIMEOUT=10
BUFFER_SIZE=65536

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)   PORT="$2";        shift 2 ;;
        -t|--timeout) TIMEOUT="$2";    shift 2 ;;
        -b|--buffer) BUFFER_SIZE="$2"; shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

HOST="${_args[0]:-}"
DOMAIN="${_args[1]:-}"
USER="${_args[2]:-}"
PASS="${_args[3]:-}"
SHARE="${_args[4]:-}"
REMOTE_DIR="${_args[5]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" || -z "${SHARE}" || -z "${REMOTE_DIR}" ]]; then
    printf 'Usage : %s [options] <host> <domain> <user> <password> <share> <remote_dir>\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -p <port>    Port SMB (défaut : 445)\n' >&2
    printf '  -t <sec>     Timeout en secondes\n' >&2
    printf '  -b <bytes>   Taille du buffer QUERY_DIRECTORY (défaut : 65536)\n' >&2
    exit 1
fi

if [[ ! "${BUFFER_SIZE}" =~ ^[0-9]+$ ]] || (( BUFFER_SIZE < 1024 )); then
    printf 'Erreur : --buffer doit être un entier >= 1024.\n' >&2
    exit 1
fi

_normalize_remote_path() {
    local path="${1:-}"
    path="${path//\//\\}"
    while [[ "${path}" == \\* ]]; do
        path="${path#\\}"
    done
    printf '%s' "${path}"
}

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — SMB2 / Listing de répertoire\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible    : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine  : %s\n' "${DOMAIN}"
    printf  '  Compte   : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '  Share    : %s\n' "${SHARE}"
    printf  '  Dossier  : %s\n' "${REMOTE_DIR}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }

_fmt_type() {
    local -i attrs="$1"
    if (( attrs & SMB2_FILE_ATTRIBUTE_DIRECTORY )); then
        printf 'dir '
    else
        printf 'file'
    fi
}

REMOTE_DIR="$(_normalize_remote_path "${REMOTE_DIR}")"

_cleanup() {
    if [[ -n "${sess:-}" && -n "${tid:-}" && -n "${file_id:-}" ]]; then
        local _cl_req _cl_raw
        local -i _cl_mid
        smb2::_next_msg_id "${sess}" _cl_mid
        smb2::close::build_request _cl_req "${file_id}" "${_cl_mid}" "${_SMB_SESSION_ID[${sess}]}" "${tid}" "$(_smb2_flags)" >/dev/null 2>&1 || true
        smb::_send "${sess}" "${_cl_req}" >/dev/null 2>&1 || true
        smb::_recv "${sess}" _cl_raw 5 >/dev/null 2>&1 || true
    fi
    [[ -n "${tid:-}" ]] && smb::session::tree_disconnect "${sess}" "${tid}" >/dev/null 2>&1 || true
    [[ -n "${sess:-}" ]] && smb::session::disconnect "${sess}" >/dev/null 2>&1 || true
}

_smb2_flags() {
    if [[ -n "${sess:-}" ]]; then
        smb::_smb2_dfs_hdr_flags "${sess}"
    else
        printf '0'
    fi
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

_info "Connexion au partage ${SHARE}..."
declare tid
if ! smb::session::tree_connect "${sess}" "${SHARE}" tid; then
    _err "TREE_CONNECT échoué sur ${SHARE}"
    smb::session::disconnect "${sess}"
    exit 1
fi
_ok "Partage connecté."

_info "Ouverture du répertoire ${REMOTE_DIR}..."
declare file_id
declare -A create_resp=()
declare create_req create_raw
declare -i create_mid
smb2::_next_msg_id "${sess}" create_mid
smb2::create::build_request create_req \
    "${REMOTE_DIR}" \
    "${create_mid}" \
    "${_SMB_SESSION_ID[${sess}]}" \
    "${tid}" \
    "${SMB2_FILE_GENERIC_READ}" \
    "${SMB2_FILE_OPEN}" \
    "$(( SMB2_FILE_DIRECTORY_FILE | SMB2_FILE_SYNCHRONOUS_IO_NONALERT ))" \
    "${SMB2_FILE_SHARE_ALL}" \
    0 \
    "$(_smb2_flags)"
smb::_send "${sess}" "${create_req}" || { _err "Envoi CREATE échoué"; _cleanup; exit 1; }
smb::_recv "${sess}" create_raw 30 || { _err "Réponse CREATE absente"; _cleanup; exit 1; }
if ! smb2::create::parse_response "${create_raw}" create_resp; then
    case "${create_resp[status]:-0}" in
        ${SMB2_STATUS_OBJECT_NAME_NOT_FOUND}|${SMB2_STATUS_OBJECT_PATH_NOT_FOUND})
            _err "Répertoire introuvable sur le partage"
            ;;
        *)
            _err "CREATE échoué"
            ;;
    esac
    _cleanup
    exit 1
fi
file_id="${create_resp[file_id]}"
_ok "Répertoire ouvert."

printf '\n'
printf '  %-4s  %-10s  %-10s  %s\n' "TYPE" "TAILLE" "ATTRS" "NOM"
printf '  %-4s  %-10s  %-10s  %s\n' "----" "----------" "----------" "---"

declare -i total=0
declare -i query_flags=${SMB2_QUERY_DIRECTORY_RESTART_SCANS}
while true; do
    declare query_req query_raw
    declare -A query_resp=()
    declare -a entries=()
    declare -i query_mid

    smb2::_next_msg_id "${sess}" query_mid
    smb2::query_directory::build_request query_req \
        "${file_id}" \
        "*" \
        "${query_mid}" \
        "${_SMB_SESSION_ID[${sess}]}" \
        "${tid}" \
        "${BUFFER_SIZE}" \
        "${query_flags}" \
        "${SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION}" \
        0 \
        "$(_smb2_flags)"

    smb::_send "${sess}" "${query_req}" || { _err "Envoi QUERY_DIRECTORY échoué"; _cleanup; exit 1; }
    smb::_recv "${sess}" query_raw 30 || { _err "Réponse QUERY_DIRECTORY absente"; _cleanup; exit 1; }
    if ! smb2::query_directory::parse_response "${query_raw}" query_resp entries; then
        _err "QUERY_DIRECTORY échoué"
        _cleanup
        exit 1
    fi

    entry=
    for entry in "${entries[@]}"; do
        IFS='|' read -r name size_lo attrs file_id_short _ <<< "${entry}"
        [[ "${name}" == "." || "${name}" == ".." ]] && continue

        type="$(_fmt_type "${attrs}")"
        size_disp="${size_lo}"
        (( attrs & SMB2_FILE_ATTRIBUTE_DIRECTORY )) && size_disp="-"
        printf -v attrs_disp '0x%08X' "${attrs}"
        printf '  %-4s  %10s  %-10s  %s\n' "${type}" "${size_disp}" "${attrs_disp}" "${name}"
        (( total++ ))
    done

    if (( query_resp[status] == SMB2_STATUS_NO_MORE_FILES || query_resp[output_buffer_length] == 0 )); then
        break
    fi

    query_flags=0
done

declare close_req close_raw
declare -A close_resp=()
declare -i close_mid
smb2::_next_msg_id "${sess}" close_mid
smb2::close::build_request close_req \
    "${file_id}" \
    "${close_mid}" \
    "${_SMB_SESSION_ID[${sess}]}" \
    "${tid}" \
    "$(_smb2_flags)"
smb::_send "${sess}" "${close_req}" || true
if smb::_recv "${sess}" close_raw 10; then
    smb2::close::parse_response "${close_raw}" close_resp >/dev/null 2>&1 || true
fi

smb::session::tree_disconnect "${sess}" "${tid}"
smb::session::disconnect "${sess}"

printf '\n'
_ok "${total} entrée(s) listée(s)"
printf '\n'
