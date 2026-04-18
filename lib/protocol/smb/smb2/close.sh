#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/close.sh -- SMB2 CLOSE (commande 0x0006)
#
# Ferme un FileId SMB2.
#

[[ -n "${_ENSH_SMB2_CLOSE:-}" ]] && return 0
readonly _ENSH_SMB2_CLOSE=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb2/header

# smb2::close::build_request <var_out> <file_id_hex32> <msg_id> <session_id> <tree_id> [header_flags]
smb2::close::build_request() {
    local -n _smb2_cl_out="$1"
    local file_id="${2^^}"
    local -i msg_id="$3"
    local session_id="${4:-0000000000000000}"
    local -i tree_id="${5:-0}"
    local -i hdr_flags="${6:-0}"

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_CLOSE}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" 1

    local body="1800"
    body+="0000"
    body+="00000000"
    body+="${file_id}"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_cl_out
}

# smb2::close::parse_response <hex_smb2_msg> <var_dict_out>
smb2::close::parse_response() {
    local msg="${1^^}"
    local -n _smb2_cl_dict="$2"

    local -A hdr
    smb2::header::parse "${msg}" hdr || return 1

    _smb2_cl_dict[status]="${hdr[status]}"

    if (( hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb2::close : status=0x$(printf '%08X' "${hdr[status]}")"
        return 1
    fi

    endian::read_le32 "${msg}" 112 _smb2_cl_dict[end_of_file_lo]
    endian::read_le32 "${msg}" 104 _smb2_cl_dict[allocation_size_lo]
    endian::read_le32 "${msg}" 120 _smb2_cl_dict[file_attributes]
}
