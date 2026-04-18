#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/write.sh -- SMB2 WRITE (commande 0x0009)
#
# Écrit des données dans un FileId SMB2.
#

[[ -n "${_ENSH_SMB2_WRITE:-}" ]] && return 0
readonly _ENSH_SMB2_WRITE=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import protocol/smb/smb2/header

readonly SMB2_WRITE_DEFAULT_LEN=65536
readonly SMB2_WRITEFLAG_NONE=0x00000000
readonly SMB2_WRITEFLAG_WRITE_THROUGH=0x00000001

# smb2::write::build_request <var_out> <file_id_hex32> <offset_int> <data_hex>
#                           <msg_id> <session_id> <tree_id>
#                           [remaining_bytes] [flags] [header_flags]
smb2::write::build_request() {
    local -n _smb2_wr_out="$1"
    local file_id="${2^^}"
    local -i offset="$3"
    local data_hex="${4^^}"
    local -i msg_id="$5"
    local session_id="${6:-0000000000000000}"
    local -i tree_id="${7:-0}"
    local -i remaining_bytes="${8:-0}"
    local -i write_flags="${9:-${SMB2_WRITEFLAG_NONE}}"
    local -i hdr_flags="${10:-0}"

    if ! hex::is_valid "${data_hex}"; then
        log::error "smb2::write : payload hex invalide"
        return 1
    fi

    local -i length=$(( ${#data_hex} / 2 ))
    local -i credit_charge=1
    (( length > 0 )) && credit_charge=$(( 1 + ((length - 1) / 65536) ))

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_WRITE}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" "${credit_charge}"

    local -i data_off=112
    local len_le off_le remain_le data_off_le flags_le
    endian::le16 "${data_off}" data_off_le
    endian::le32 "${length}" len_le
    endian::le64 $(( (offset >> 32) & 0xFFFFFFFF )) $(( offset & 0xFFFFFFFF )) off_le
    endian::le32 "${remaining_bytes}" remain_le
    endian::le32 "${write_flags}" flags_le

    local body="3100"
    body+="${data_off_le}"
    body+="${len_le}"
    body+="${off_le}"
    body+="${file_id}"
    body+="00000000"
    body+="${remain_le}"
    body+="0000"
    body+="0000"
    body+="${flags_le}"
    body+="${data_hex}"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_wr_out
    log::debug "smb2::write : offset=${offset} len=${length}"
}

# smb2::write::parse_response <hex_smb2_msg> <var_dict_out>
smb2::write::parse_response() {
    local msg="${1^^}"
    local -n _smb2_wr_dict="$2"

    local -A hdr
    smb2::header::parse "${msg}" hdr || return 1

    _smb2_wr_dict[status]="${hdr[status]}"

    if (( hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb2::write : status=0x$(printf '%08X' "${hdr[status]}")"
        return 1
    fi

    endian::read_le32 "${msg}" 68 _smb2_wr_dict[count]
    endian::read_le32 "${msg}" 72 _smb2_wr_dict[remaining]
    endian::read_le16 "${msg}" 76 _smb2_wr_dict[write_channel_info_offset]
    endian::read_le16 "${msg}" 78 _smb2_wr_dict[write_channel_info_length]

    log::debug "smb2::write : count=${_smb2_wr_dict[count]} remaining=${_smb2_wr_dict[remaining]}"
}
