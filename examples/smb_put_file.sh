#!/usr/bin/env bash
#
# examples/smb_put_file.sh -- Upload de fichier via SMB2
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/smb/session
ensh::import protocol/smb/smb2/create
ensh::import protocol/smb/smb2/write
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
LOCAL_SRC="${_args[5]:-}"
REMOTE_PATH="${_args[6]:-}"

if [[ -z "${HOST}" || -z "${DOMAIN}" || -z "${USER}" || -z "${PASS}" || -z "${SHARE}" || -z "${LOCAL_SRC}" || -z "${REMOTE_PATH}" ]]; then
    printf 'Usage : %s [options] <host> <domain> <user> <password> <share> <local_src> <remote_path>\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -p <port>    Port SMB (défaut : 445)\n' >&2
    printf '  -t <sec>     Timeout en secondes\n' >&2
    printf '  -c <bytes>   Taille d''une écriture SMB2 WRITE (défaut : 65536)\n' >&2
    exit 1
fi

if [[ ! "${CHUNK_SIZE}" =~ ^[0-9]+$ ]] || (( CHUNK_SIZE < 1 )); then
    printf 'Erreur : --chunk doit être un entier strictement positif.\n' >&2
    exit 1
fi

if [[ ! -r "${LOCAL_SRC}" ]]; then
    printf 'Erreur : fichier local introuvable ou illisible: %s\n' "${LOCAL_SRC}" >&2
    exit 1
fi

if ! command -v xxd >/dev/null 2>&1; then
    printf 'Erreur : xxd est requis pour lire le fichier local.\n' >&2
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

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — SMB2 / Upload de fichier\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Cible    : %s:%s\n' "${HOST}" "${PORT}"
    printf  '  Domaine  : %s\n' "${DOMAIN}"
    printf  '  Compte   : %s\\%s\n' "${DOMAIN}" "${USER}"
    printf  '  Share    : %s\n' "${SHARE}"
    printf  '  Source   : %s\n' "${LOCAL_SRC}"
    printf  '  Dest     : %s\n' "${REMOTE_PATH}"
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }

REMOTE_PATH="$(_normalize_remote_path "${REMOTE_PATH}")"

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
    "${SMB2_FILE_GENERIC_WRITE}" \
    "${SMB2_FILE_OVERWRITE_IF}" \
    "$(( SMB2_FILE_NON_DIRECTORY_FILE | SMB2_FILE_SYNCHRONOUS_IO_NONALERT ))" \
    "${SMB2_FILE_SHARE_ALL}" \
    0 \
    "$(_smb2_flags)"
smb::_send "${sess}" "${create_req}" || { _err "Envoi CREATE échoué"; _cleanup; exit 1; }
smb::_recv "${sess}" create_raw 30 || { _err "Réponse CREATE absente"; _cleanup; exit 1; }
if ! smb2::create::parse_response "${create_raw}" create_resp; then
    case "${create_resp[status]:-0}" in
        ${SMB2_STATUS_OBJECT_PATH_NOT_FOUND}|${SMB2_STATUS_OBJECT_NAME_NOT_FOUND})
            _err "Chemin distant introuvable sur le partage"
            ;;
        ${SMB2_STATUS_FILE_IS_A_DIRECTORY})
            _err "Le chemin distant cible un répertoire, pas un fichier"
            ;;
        ${SMB2_STATUS_ACCESS_DENIED})
            _err "Accès refusé sur le fichier distant"
            ;;
        *)
            _err "CREATE échoué"
            ;;
    esac
    _cleanup
    exit 1
fi
file_id="${create_resp[file_id]}"
_ok "Fichier distant prêt."

printf '\n'
_info "Upload en cours..."

declare -i offset=0
declare -i total=0
while IFS= read -r chunk_hex || [[ -n "${chunk_hex}" ]]; do
    chunk_hex="${chunk_hex^^}"
    [[ -z "${chunk_hex}" ]] && continue

    pending_hex="${chunk_hex}"
    while [[ -n "${pending_hex}" ]]; do
        declare write_req write_raw
        declare -A write_resp=()
        declare -i write_mid
        declare -i pending_len=$(( ${#pending_hex} / 2 ))

        smb2::_next_msg_id "${sess}" write_mid
        smb2::write::build_request write_req \
            "${file_id}" \
            "${offset}" \
            "${pending_hex}" \
            "${write_mid}" \
            "${_SMB_SESSION_ID[${sess}]}" \
            "${tid}" \
            0 \
            "${SMB2_WRITEFLAG_NONE}" \
            "$(_smb2_flags)" || { _err "Construction WRITE échouée"; _cleanup; exit 1; }

        smb::_send "${sess}" "${write_req}" || { _err "Envoi WRITE échoué"; _cleanup; exit 1; }
        smb::_recv "${sess}" write_raw 30 || { _err "Réponse WRITE absente"; _cleanup; exit 1; }
        if ! smb2::write::parse_response "${write_raw}" write_resp; then
            _err "WRITE échoué"
            _cleanup
            exit 1
        fi

        if (( write_resp[count] <= 0 )); then
            _err "WRITE n'a écrit aucun octet"
            _cleanup
            exit 1
        fi

        (( total += write_resp[count] ))
        (( offset += write_resp[count] ))

        if (( write_resp[count] >= pending_len )); then
            pending_hex=""
        else
            pending_hex="${pending_hex:$(( write_resp[count] * 2 ))}"
        fi
    done
done < <(xxd -p -c "${CHUNK_SIZE}" "${LOCAL_SRC}")

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
_ok "${total} octet(s) envoyé(s) vers ${REMOTE_PATH}"
printf '\n'
