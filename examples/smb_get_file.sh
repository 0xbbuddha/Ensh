#!/usr/bin/env bash
#
# examples/smb_get_file.sh -- Téléchargement de fichier via SMB2
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/smb/smb2/create
ensh::import protocol/smb/smb2/read
ensh::import protocol/smb/smb2/close

PORT=445
TIMEOUT=10
CHUNK_SIZE=65536

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)    PORT="$2";       shift 2 ;;
        -t|--timeout) TIMEOUT="$2";    shift 2 ;;
        -c|--chunk)   CHUNK_SIZE="$2"; shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

HOST="${_args[0]:-}"
DOMAIN="${_args[1]:-}"
USER="${_args[2]:-}"
PASS="${_args[3]:-}"
SHARE="${_args[4]:-}"
REMOTE_PATH="${_args[5]:-}"
LOCAL_DEST="${_args[6]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" || -z "${SHARE}" || -z "${REMOTE_PATH}" ]]; then
    printf 'Usage : %s [options] <host> <domain> <user> <password> <share> <remote_path> [local_dest]\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -p <port>    Port SMB (défaut : 445)\n' >&2
    printf '  -t <sec>     Timeout en secondes\n' >&2
    printf '  -c <bytes>   Taille d''une lecture SMB2 READ (défaut : 65536)\n' >&2
    exit 1
fi

if [[ ! "${CHUNK_SIZE}" =~ ^[0-9]+$ ]] || (( CHUNK_SIZE < 1 )); then
    printf 'Erreur : --chunk doit être un entier strictement positif.\n' >&2
    exit 1
fi

if ! command -v xxd >/dev/null 2>&1; then
    printf 'Erreur : xxd est requis pour écrire le fichier local.\n' >&2
    exit 1
fi

_normalize_remote_path() {
    local path="$1"
    path="${path//\//\\}"
    while [[ "${path}" == \\* ]]; do
        path="${path#\\}"
    done
    printf '%s' "${path}"
}

_default_local_name() {
    local path="$1"
    local base="${path##*\\}"
    [[ -z "${base}" || "${base}" == "${path}" ]] && base="${path##*/}"
    [[ -z "${base}" ]] && base="download.bin"
    printf '%s' "${base}"
}

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — SMB2 / Téléchargement de fichier\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible    : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine  : %s\n' "${DOMAIN}"
    printf  '  Compte   : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '  Share    : %s\n' "${SHARE}"
    printf  '  Fichier  : %s\n' "${REMOTE_PATH}"
    printf  '  Sortie   : %s\n' "${LOCAL_DEST}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }

REMOTE_PATH="$(_normalize_remote_path "${REMOTE_PATH}")"
LOCAL_DEST="${LOCAL_DEST:-$(_default_local_name "${REMOTE_PATH}")}"

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

_info "Ouverture de ${REMOTE_PATH}..."
declare file_id
declare -A create_resp=()
declare create_req create_raw
declare -i create_mid
smb2::_next_msg_id "${sess}" create_mid
smb2::create::build_request create_req \
    "${REMOTE_PATH}" \
    "${create_mid}" \
    "${_SMB_SESSION_ID[${sess}]}" \
    "${tid}" \
    "${SMB2_FILE_GENERIC_READ}" \
    "${SMB2_FILE_OPEN}" \
    "$(( SMB2_FILE_NON_DIRECTORY_FILE | SMB2_FILE_SYNCHRONOUS_IO_NONALERT ))" \
    "${SMB2_FILE_SHARE_ALL}" \
    0 \
    "$(_smb2_flags)"
smb::_send "${sess}" "${create_req}" || { _err "Envoi CREATE échoué"; _cleanup; exit 1; }
smb::_recv "${sess}" create_raw 30 || { _err "Réponse CREATE absente"; _cleanup; exit 1; }
if ! smb2::create::parse_response "${create_raw}" create_resp; then
    case "${create_resp[status]:-0}" in
        ${SMB2_STATUS_OBJECT_NAME_NOT_FOUND}|${SMB2_STATUS_OBJECT_PATH_NOT_FOUND})
            _err "Fichier introuvable sur le partage"
            ;;
        ${SMB2_STATUS_FILE_IS_A_DIRECTORY})
            _err "Le chemin distant cible un répertoire, pas un fichier"
            ;;
        *)
            _err "CREATE échoué"
            ;;
    esac
    _cleanup
    exit 1
fi
file_id="${create_resp[file_id]}"
_ok "Fichier ouvert."

: > "${LOCAL_DEST}"

printf '\n'
_info "Téléchargement en cours..."

declare -i offset=0
declare -i total=0
while true; do
    declare read_req read_raw
    declare -A read_resp=()
    declare -i read_mid

    smb2::_next_msg_id "${sess}" read_mid
    smb2::read::build_request read_req \
        "${file_id}" \
        "${offset}" \
        "${CHUNK_SIZE}" \
        "${read_mid}" \
        "${_SMB_SESSION_ID[${sess}]}" \
        "${tid}" \
        0 0 \
        "$(_smb2_flags)"

    smb::_send "${sess}" "${read_req}" || { _err "Envoi READ échoué"; _cleanup; exit 1; }
    smb::_recv "${sess}" read_raw 30 || { _err "Réponse READ absente"; _cleanup; exit 1; }
    if ! smb2::read::parse_response "${read_raw}" read_resp; then
        _err "READ échoué"
        _cleanup
        exit 1
    fi

    if [[ -n "${read_resp[data]:-}" ]]; then
        printf '%s' "${read_resp[data]}" | xxd -r -p >> "${LOCAL_DEST}"
    fi

    (( total += read_resp[data_len] ))

    if (( read_resp[status] == SMB2_STATUS_END_OF_FILE || read_resp[data_len] == 0 || read_resp[data_remaining] == 0 )); then
        break
    fi

    (( offset += read_resp[data_len] ))
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
_ok "${total} octet(s) téléchargé(s) vers ${LOCAL_DEST}"
printf '\n'
