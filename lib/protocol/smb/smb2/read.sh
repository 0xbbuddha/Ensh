#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/read.sh -- SMB2 READ (commande 0x0008)
#
# Lit des données à partir d'un FileId SMB2.
#

[[ -n "${_ENSH_SMB2_READ:-}" ]] && return 0
readonly _ENSH_SMB2_READ=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import protocol/smb/smb2/header

readonly SMB2_READ_DEFAULT_LEN=65536

# smb2::read::build_request <var_out> <file_id_hex32> <offset_int> <length_int>
#                          <msg_id> <session_id> <tree_id>
#                          [remaining_bytes] [minimum_count] [header_flags]
smb2::read::build_request() {
    local -n _smb2_rd_out="$1"
    local file_id="${2^^}"
    local -i offset="$3"
    local -i length="$4"
    local -i msg_id="$5"
    local session_id="${6:-0000000000000000}"
    local -i tree_id="${7:-0}"
    local -i remaining_bytes="${8:-0}"
    local -i minimum_count="${9:-0}"
    local -i hdr_flags="${10:-0}"
    local -i credit_charge=1
    (( length > 0 )) && credit_charge=$(( 1 + ((length - 1) / 65536) ))

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_READ}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" "${credit_charge}"

    local len_le off_le min_le remain_le
    endian::le32 "${length}" len_le
    endian::le64 $(( (offset >> 32) & 0xFFFFFFFF )) $(( offset & 0xFFFFFFFF )) off_le
    endian::le32 "${minimum_count}" min_le
    endian::le32 "${remaining_bytes}" remain_le

    local body="3100"
    body+="50"
    body+="00"
    body+="${len_le}"
    body+="${off_le}"
    body+="${file_id}"
    body+="${min_le}"
    body+="00000000"
    body+="${remain_le}"
    body+="0000"
    body+="0000"
    body+="00"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_rd_out
    log::debug "smb2::read : offset=${offset} len=${length}"
}

# smb2::read::parse_response <hex_smb2_msg> <var_dict_out>
smb2::read::parse_response() {
    local msg="${1^^}"
    local -n _smb2_rd_dict="$2"

    local -A hdr
    smb2::header::parse "${msg}" hdr || return 1

    _smb2_rd_dict[status]="${hdr[status]}"

    if (( hdr[status] != SMB2_STATUS_SUCCESS && hdr[status] != SMB2_STATUS_END_OF_FILE )); then
        log::error "smb2::read : status=0x$(printf '%08X' "${hdr[status]}")"
        return 1
    fi

    _smb2_rd_dict[data_offset]="$(( 16#${msg:132:2} ))"
    endian::read_le32 "${msg}" 68 _smb2_rd_dict[data_len]
    endian::read_le32 "${msg}" 72 _smb2_rd_dict[data_remaining]

    local -i data_off="${_smb2_rd_dict[data_offset]}"
    local -i data_len="${_smb2_rd_dict[data_len]}"

    if (( data_len > 0 )); then
        hex::slice "${msg}" "${data_off}" "${data_len}" _smb2_rd_dict[data]
    else
        _smb2_rd_dict[data]=""
    fi

    log::debug "smb2::read : len=${data_len} remaining=${_smb2_rd_dict[data_remaining]} status=0x$(printf '%08X' "${hdr[status]}")"
}
