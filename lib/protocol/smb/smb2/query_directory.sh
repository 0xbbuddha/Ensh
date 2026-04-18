#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/query_directory.sh -- SMB2 QUERY_DIRECTORY (commande 0x000F)
#
# Énumère les entrées d'un répertoire ouvert via SMB2 CREATE.
#

[[ -n "${_ENSH_SMB2_QUERY_DIRECTORY:-}" ]] && return 0
readonly _ENSH_SMB2_QUERY_DIRECTORY=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/smb/smb2/header

readonly SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION=0x26

readonly SMB2_QUERY_DIRECTORY_RESTART_SCANS=0x01
readonly SMB2_QUERY_DIRECTORY_RETURN_SINGLE=0x02
readonly SMB2_QUERY_DIRECTORY_INDEX_SPECIFIED=0x04
readonly SMB2_QUERY_DIRECTORY_REOPEN=0x10

readonly SMB2_QUERY_DIRECTORY_DEFAULT_LEN=65536

readonly SMB2_FILE_ATTRIBUTE_READONLY=0x00000001
readonly SMB2_FILE_ATTRIBUTE_HIDDEN=0x00000002
readonly SMB2_FILE_ATTRIBUTE_SYSTEM=0x00000004
readonly SMB2_FILE_ATTRIBUTE_DIRECTORY=0x00000010
readonly SMB2_FILE_ATTRIBUTE_ARCHIVE=0x00000020
readonly SMB2_FILE_ATTRIBUTE_NORMAL=0x00000080

# smb2::query_directory::build_request <var_out> <file_id_hex32> <pattern>
#                                     <msg_id> <session_id> <tree_id>
#                                     [output_len] [flags] [info_class]
#                                     [file_index] [header_flags]
smb2::query_directory::build_request() {
    local -n _smb2_qd_out="$1"
    local file_id="${2^^}"
    local pattern="${3:-*}"
    local -i msg_id="$4"
    local session_id="${5:-0000000000000000}"
    local -i tree_id="${6:-0}"
    local -i output_len="${7:-${SMB2_QUERY_DIRECTORY_DEFAULT_LEN}}"
    local -i query_flags="${8:-${SMB2_QUERY_DIRECTORY_RESTART_SCANS}}"
    local -i info_class="${9:-${SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION}}"
    local -i file_index="${10:-0}"
    local -i hdr_flags="${11:-0}"

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_QUERY_DIRECTORY}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" 1

    local pattern_utf16=""
    if [[ -n "${pattern}" ]]; then
        utf16::encode_le "${pattern}" pattern_utf16
    fi

    local -i pattern_len=$(( ${#pattern_utf16} / 2 ))
    local -i pattern_off=0
    (( pattern_len > 0 )) && pattern_off=96

    local file_index_le file_name_off_le file_name_len_le out_len_le
    endian::le32 "${file_index}" file_index_le
    endian::le16 "${pattern_off}" file_name_off_le
    endian::le16 "${pattern_len}" file_name_len_le
    endian::le32 "${output_len}" out_len_le

    local body="2100"
    printf -v body '%s%02X%02X' "${body}" "$(( info_class & 0xFF ))" "$(( query_flags & 0xFF ))"
    body+="${file_index_le}"
    body+="${file_id}"
    body+="${file_name_off_le}"
    body+="${file_name_len_le}"
    body+="${out_len_le}"
    body+="${pattern_utf16}"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_qd_out
    log::debug "smb2::query_directory : pattern='${pattern}' flags=0x$(printf '%02X' "${query_flags}") out=${output_len}"
}

# smb2::query_directory::_parse_file_id_full_directory_info <buffer_hex> <var_list_out>
#
# Chaque entrée est renvoyée sous la forme :
#   name|size_lo|attributes|file_id_hex8|file_index
smb2::query_directory::_parse_file_id_full_directory_info() {
    local buffer="${1^^}"
    local -n _smb2_qd_entries="$2"
    _smb2_qd_entries=()

    local -i buf_len=$(( ${#buffer} / 2 ))
    local -i off=0

    while (( off + 80 <= buf_len )); do
        local -i next_off file_index end_of_file_lo attrs name_len
        local file_id name_hex name=""

        endian::read_le32 "${buffer}" "${off}" next_off
        endian::read_le32 "${buffer}" "$(( off + 4 ))" file_index
        endian::read_le32 "${buffer}" "$(( off + 40 ))" end_of_file_lo
        endian::read_le32 "${buffer}" "$(( off + 56 ))" attrs
        endian::read_le32 "${buffer}" "$(( off + 60 ))" name_len

        if (( off + 80 + name_len > buf_len )); then
            log::warn "smb2::query_directory : entrée tronquée à l'offset ${off}"
            break
        fi

        hex::slice "${buffer}" "$(( off + 72 ))" 8 file_id
        if (( name_len > 0 )); then
            hex::slice "${buffer}" "$(( off + 80 ))" "${name_len}" name_hex
            utf16::decode_le "${name_hex}" name
        fi

        _smb2_qd_entries+=("${name}|${end_of_file_lo}|${attrs}|${file_id}|${file_index}")

        if (( next_off == 0 )); then
            break
        fi

        if (( next_off < 80 )); then
            log::warn "smb2::query_directory : NextEntryOffset invalide (${next_off})"
            break
        fi

        off=$(( off + next_off ))
    done
}

# smb2::query_directory::parse_response <hex_smb2_msg> <var_dict_out> [var_entries_out]
smb2::query_directory::parse_response() {
    local msg="${1^^}"
    local -n _smb2_qd_dict="$2"
    local _entries_name="${3:-}"

    local -A hdr
    smb2::header::parse "${msg}" hdr || return 1

    _smb2_qd_dict[status]="${hdr[status]}"

    if (( hdr[status] != SMB2_STATUS_SUCCESS &&
          hdr[status] != SMB2_STATUS_NO_MORE_FILES &&
          hdr[status] != SMB2_STATUS_BUFFER_OVERFLOW )); then
        log::error "smb2::query_directory : status=0x$(printf '%08X' "${hdr[status]}")"
        return 1
    fi

    endian::read_le16 "${msg}" 66 _smb2_qd_dict[output_buffer_offset]
    endian::read_le32 "${msg}" 68 _smb2_qd_dict[output_buffer_length]

    local -i out_off="${_smb2_qd_dict[output_buffer_offset]}"
    local -i out_len="${_smb2_qd_dict[output_buffer_length]}"

    if (( out_off > 0 && out_len > 0 )); then
        hex::slice "${msg}" "${out_off}" "${out_len}" _smb2_qd_dict[buffer]
    else
        _smb2_qd_dict[buffer]=""
    fi

    if [[ -n "${_entries_name}" ]]; then
        local -n _smb2_qd_entries_ref="${_entries_name}"
        smb2::query_directory::_parse_file_id_full_directory_info "${_smb2_qd_dict[buffer]}" _smb2_qd_entries_ref
    fi

    log::debug "smb2::query_directory : status=0x$(printf '%08X' "${hdr[status]}") len=${out_len}"
}
