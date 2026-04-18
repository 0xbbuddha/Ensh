#!/usr/bin/env bash
#
# tests/protocol/smb/test_smb2_query_directory.sh -- Tests SMB2 QUERY_DIRECTORY
#

ensh::import encoding/utf16
ensh::import protocol/smb/smb2/query_directory

_test::smb2_qd_entry() {
    local name="$1"
    local -i size_lo="$2"
    local -i attrs="$3"
    local file_id="${4^^}"
    local -i next_off="$5"
    local -i file_index="${6:-0}"
    local -n _test_smb2_qd_out="$7"

    local name_utf16 next_le index_le eof_le attrs_le name_len_le
    utf16::encode_le "${name}" name_utf16
    endian::le32 "${next_off}" next_le
    endian::le32 "${file_index}" index_le
    endian::le64 0 "${size_lo}" eof_le
    endian::le32 "${attrs}" attrs_le
    endian::le32 "$(( ${#name_utf16} / 2 ))" name_len_le

    _test_smb2_qd_out="${next_le}"
    _test_smb2_qd_out+="${index_le}"
    _test_smb2_qd_out+="0000000000000000"
    _test_smb2_qd_out+="0000000000000000"
    _test_smb2_qd_out+="0000000000000000"
    _test_smb2_qd_out+="0000000000000000"
    _test_smb2_qd_out+="${eof_le}"
    _test_smb2_qd_out+="${eof_le}"
    _test_smb2_qd_out+="${attrs_le}"
    _test_smb2_qd_out+="${name_len_le}"
    _test_smb2_qd_out+="00000000"
    _test_smb2_qd_out+="00000000"
    _test_smb2_qd_out+="${file_id}"
    _test_smb2_qd_out+="${name_utf16}"

    local -i entry_len=$(( ${#_test_smb2_qd_out} / 2 ))
    if (( next_off > entry_len )); then
        local padding=""
        printf -v padding '%0*d' "$(( (next_off - entry_len) * 2 ))" 0
        _test_smb2_qd_out+="${padding}"
    fi
}

test::smb2_query_directory_build_request() {
    local req
    smb2::query_directory::build_request req \
        "00112233445566778899AABBCCDDEEFF" \
        "*" \
        15 \
        "0000000000000000" \
        4

    assert::not_empty "${req}" "QUERY_DIRECTORY request non vide"
    assert::equal "${req:0:8}" "00000062" "NBT length QUERY_DIRECTORY = 98 octets"
    assert::equal "${req:136:4}" "2100" "StructureSize QUERY_DIRECTORY = 33"
    assert::equal "${req:140:2}" "26" "InfoClass = FileIdFullDirectoryInformation"
    assert::equal "${req:142:2}" "01" "Flags = RESTART_SCANS"
    assert::equal "${req:184:4}" "6000" "FileNameOffset = 96"
    assert::equal "${req:188:4}" "0200" "FileNameLength = 2 octets pour '*'"
    assert::equal "${req:192:8}" "00000100" "OutputBufferLength = 65536"
    assert::equal "${req:200:4}" "2A00" "pattern UTF-16LE '*'"
}

test::smb2_query_directory_parse_response() {
    local entry1 entry2 buffer_len_le hdr msg
    _test::smb2_qd_entry "." 0 "${SMB2_FILE_ATTRIBUTE_DIRECTORY}" "8877665544332211" 88 1 entry1
    _test::smb2_qd_entry "loot" 1337 "${SMB2_FILE_ATTRIBUTE_ARCHIVE}" "00FFEEDDCCBBAA99" 0 2 entry2

    endian::le32 $(( (${#entry1} + ${#entry2}) / 2 )) buffer_len_le
    smb2::header::build hdr "${SMB2_CMD_QUERY_DIRECTORY}" 16 "0000000000000000" 4

    msg="${hdr}"
    msg+="0900"
    msg+="4800"
    msg+="${buffer_len_le}"
    msg+="${entry1}${entry2}"

    local -A parsed=()
    local -a entries=()
    smb2::query_directory::parse_response "${msg}" parsed entries

    assert::equal "${parsed[output_buffer_offset]}" "72" "OutputBufferOffset lu"
    assert::equal "${parsed[output_buffer_length]}" "$(( (${#entry1} + ${#entry2}) / 2 ))" "OutputBufferLength lu"
    assert::equal "${#entries[@]}" "2" "deux entrées extraites"

    IFS='|' read -r name1 size1 attrs1 fileid1 index1 <<< "${entries[0]}"
    IFS='|' read -r name2 size2 attrs2 fileid2 index2 <<< "${entries[1]}"

    assert::equal "${name1}" "." "premier nom décodé"
    assert::equal "${attrs1}" "16" "attribut dossier lu"
    assert::equal "${name2}" "loot" "deuxième nom décodé"
    assert::equal "${size2}" "1337" "taille basse lue"
    assert::equal "${fileid2}" "00FFEEDDCCBBAA99" "FileId extrait"
    assert::equal "${index2}" "2" "FileIndex extrait"
}
