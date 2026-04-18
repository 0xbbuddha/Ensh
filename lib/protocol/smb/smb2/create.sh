#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/create.sh -- SMB2 CREATE (commande 0x0005)
#
# Ouvre un fichier ou un répertoire sur un partage SMB2.
#

[[ -n "${_ENSH_SMB2_CREATE:-}" ]] && return 0
readonly _ENSH_SMB2_CREATE=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/smb/smb2/header

# -- Constantes CREATE --------------------------------------------------------

readonly SMB2_OPLOCK_LEVEL_NONE=0x00

readonly SMB2_IMPERSONATION_ANONYMOUS=0x00000000
readonly SMB2_IMPERSONATION_IDENTIFICATION=0x00000001
readonly SMB2_IMPERSONATION_IMPERSONATION=0x00000002
readonly SMB2_IMPERSONATION_DELEGATE=0x00000003

readonly SMB2_FILE_READ_DATA=0x00000001
readonly SMB2_FILE_WRITE_DATA=0x00000002
readonly SMB2_FILE_APPEND_DATA=0x00000004
readonly SMB2_FILE_READ_EA=0x00000008
readonly SMB2_FILE_WRITE_EA=0x00000010
readonly SMB2_FILE_READ_ATTRIBUTES=0x00000080
readonly SMB2_FILE_WRITE_ATTRIBUTES=0x00000100
readonly SMB2_READ_CONTROL=0x00020000
readonly SMB2_SYNCHRONIZE=0x00100000
readonly SMB2_FILE_GENERIC_READ=0x00120089
readonly SMB2_FILE_GENERIC_WRITE=0x00120116

readonly SMB2_FILE_SHARE_READ=0x00000001
readonly SMB2_FILE_SHARE_WRITE=0x00000002
readonly SMB2_FILE_SHARE_DELETE=0x00000004
readonly SMB2_FILE_SHARE_ALL=0x00000007

readonly SMB2_FILE_SUPERSEDE=0x00000000
readonly SMB2_FILE_OPEN=0x00000001
readonly SMB2_FILE_CREATE=0x00000002
readonly SMB2_FILE_OPEN_IF=0x00000003
readonly SMB2_FILE_OVERWRITE=0x00000004
readonly SMB2_FILE_OVERWRITE_IF=0x00000005

readonly SMB2_FILE_DIRECTORY_FILE=0x00000001
readonly SMB2_FILE_NON_DIRECTORY_FILE=0x00000040
readonly SMB2_FILE_SYNCHRONOUS_IO_NONALERT=0x00000020

readonly SMB2_CREATE_ACTION_SUPERSEDED=0x00000000
readonly SMB2_CREATE_ACTION_OPENED=0x00000001
readonly SMB2_CREATE_ACTION_CREATED=0x00000002
readonly SMB2_CREATE_ACTION_OVERWRITTEN=0x00000003

# -- Construction -------------------------------------------------------------

# smb2::create::build_request <var_out> <filename> <msg_id> <session_id> <tree_id>
#                            [desired_access] [create_disposition] [create_options]
#                            [share_access] [file_attributes] [header_flags]
smb2::create::build_request() {
    local -n _smb2_cr_out="$1"
    local filename="$2"
    local -i msg_id="$3"
    local session_id="${4:-0000000000000000}"
    local -i tree_id="${5:-0}"
    local -i desired_access="${6:-${SMB2_FILE_GENERIC_READ}}"
    local -i create_disposition="${7:-${SMB2_FILE_OPEN}}"
    local -i create_options="${8:-$(( SMB2_FILE_NON_DIRECTORY_FILE | SMB2_FILE_SYNCHRONOUS_IO_NONALERT ))}"
    local -i share_access="${9:-${SMB2_FILE_SHARE_ALL}}"
    local -i file_attributes="${10:-0}"
    local -i hdr_flags="${11:-0}"

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_CREATE}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" 1

    local name_utf16
    utf16::encode_le "${filename}" name_utf16
    local -i name_len=$(( ${#name_utf16} / 2 ))

    local -i name_off=0
    (( name_len > 0 )) && name_off=120

    local imp_le desired_le attrs_le share_le disp_le opts_le name_off_le name_len_le
    endian::le32 "${SMB2_IMPERSONATION_IMPERSONATION}" imp_le
    endian::le32 "${desired_access}" desired_le
    endian::le32 "${file_attributes}" attrs_le
    endian::le32 "${share_access}" share_le
    endian::le32 "${create_disposition}" disp_le
    endian::le32 "${create_options}" opts_le
    endian::le16 "${name_off}" name_off_le
    endian::le16 "${name_len}" name_len_le

    local body="3900"
    body+="00"
    body+="$(printf '%02X' "${SMB2_OPLOCK_LEVEL_NONE}")"
    body+="${imp_le}"
    body+="0000000000000000"
    body+="0000000000000000"
    body+="${desired_le}"
    body+="${attrs_le}"
    body+="${share_le}"
    body+="${disp_le}"
    body+="${opts_le}"
    body+="${name_off_le}"
    body+="${name_len_le}"
    body+="00000000"
    body+="00000000"
    body+="${name_utf16}"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_cr_out
    log::debug "smb2::create : filename='${filename}' access=0x$(printf '%08X' "${desired_access}") opts=0x$(printf '%08X' "${create_options}")"
}

# -- Parsing ------------------------------------------------------------------

# smb2::create::parse_response <hex_smb2_msg> <var_dict_out>
smb2::create::parse_response() {
    local msg="${1^^}"
    local -n _smb2_cr_dict="$2"

    local -A hdr
    smb2::header::parse "${msg}" hdr || return 1

    _smb2_cr_dict[status]="${hdr[status]}"

    if (( hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb2::create : status=0x$(printf '%08X' "${hdr[status]}")"
        return 1
    fi

    endian::read_le32 "${msg}" 68 _smb2_cr_dict[create_action]
    endian::read_le32 "${msg}" 120 _smb2_cr_dict[file_attributes]
    endian::read_le32 "${msg}" 112 _smb2_cr_dict[end_of_file_lo]
    endian::read_le32 "${msg}" 104 _smb2_cr_dict[allocation_size_lo]
    hex::slice "${msg}" 128 16 _smb2_cr_dict[file_id]

    log::debug "smb2::create : action=${_smb2_cr_dict[create_action]} file_id=${_smb2_cr_dict[file_id]:0:16}..."
}
