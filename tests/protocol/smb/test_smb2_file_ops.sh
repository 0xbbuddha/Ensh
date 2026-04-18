#!/usr/bin/env bash
#
# tests/protocol/smb/test_smb2_file_ops.sh -- Tests SMB2 CREATE / READ / CLOSE
#

ensh::import protocol/smb/smb2/create
ensh::import protocol/smb/smb2/read
ensh::import protocol/smb/smb2/close

test::smb2_create_build_request() {
    local req
    smb2::create::build_request req "loot\\flag.txt" 7 "0000000000000000" 3

    assert::not_empty "${req}" "CREATE request non vide"
    assert::equal "${req:0:8}" "00000092" "NBT length CREATE = 146 octets"
    assert::equal "${req:8:8}" "${SMB2_PROTO_SIG}" "signature SMB2 présente"
    assert::equal "${req:136:4}" "3900" "StructureSize CREATE = 57"
    assert::equal "${req:228:4}" "1A00" "NameLength doit refléter 13 caractères UTF-16LE"
    assert::equal "${req:248:28}" "6C006F006F0074005C0066006C00" "le chemin UTF-16LE doit commencer correctement"
}

test::smb2_create_parse_response() {
    local hdr alloc eof msg
    smb2::header::build hdr "${SMB2_CMD_CREATE}" 9 "0000000000000000" 3
    endian::le64 0 4096 alloc
    endian::le64 0 1234 eof

    msg="${hdr}"
    msg+="5900"
    msg+="00"
    msg+="00"
    msg+="01000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="${alloc}"
    msg+="${eof}"
    msg+="20000000"
    msg+="00000000"
    msg+="887766554433221100FFEEDDCCBBAA99"
    msg+="00000000"
    msg+="00000000"

    local -A parsed=()
    smb2::create::parse_response "${msg}" parsed

    assert::equal "${parsed[create_action]}" "1" "CreateAction OPENED lu"
    assert::equal "${parsed[file_attributes]}" "32" "FileAttributes lus"
    assert::equal "${parsed[end_of_file_lo]}" "1234" "taille EOF basse lue"
    assert::equal "${parsed[file_id]}" "887766554433221100FFEEDDCCBBAA99" "FileId extrait"
}

test::smb2_read_build_request() {
    local req
    smb2::read::build_request req "00112233445566778899AABBCCDDEEFF" 4096 1024 11 "0000000000000000" 4

    assert::not_empty "${req}" "READ request non vide"
    assert::equal "${req:0:8}" "00000071" "NBT length READ = 113 octets"
    assert::equal "${req:136:4}" "3100" "StructureSize READ = 49"
    assert::equal "${req:144:8}" "00040000" "Length READ = 1024"
    assert::equal "${req:152:16}" "0010000000000000" "Offset READ = 4096"
}

test::smb2_read_parse_response() {
    local hdr msg
    smb2::header::build hdr "${SMB2_CMD_READ}" 12 "0000000000000000" 4

    msg="${hdr}"
    msg+="1100"
    msg+="50"
    msg+="00"
    msg+="05000000"
    msg+="07000000"
    msg+="00000000"
    msg+="48454C4C4F"

    local -A parsed=()
    smb2::read::parse_response "${msg}" parsed

    assert::equal "${parsed[data_offset]}" "80" "DataOffset lu"
    assert::equal "${parsed[data_len]}" "5" "DataLength lu"
    assert::equal "${parsed[data_remaining]}" "7" "DataRemaining lu"
    assert::equal "${parsed[data]}" "48454C4C4F" "payload lu"
}

test::smb2_close_build_request() {
    local req
    smb2::close::build_request req "00112233445566778899AABBCCDDEEFF" 13 "0000000000000000" 4

    assert::not_empty "${req}" "CLOSE request non vide"
    assert::equal "${req:0:8}" "00000058" "NBT length CLOSE = 88 octets"
    assert::equal "${req:136:4}" "1800" "StructureSize CLOSE = 24"
    assert::equal "${req:152:32}" "00112233445566778899AABBCCDDEEFF" "FileId présent dans le body"
}

test::smb2_close_parse_response() {
    local hdr alloc eof msg
    smb2::header::build hdr "${SMB2_CMD_CLOSE}" 14 "0000000000000000" 4
    endian::le64 0 4096 alloc
    endian::le64 0 1234 eof

    msg="${hdr}"
    msg+="3C00"
    msg+="0000"
    msg+="00000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="0000000000000000"
    msg+="${alloc}"
    msg+="${eof}"
    msg+="20000000"

    local -A parsed=()
    smb2::close::parse_response "${msg}" parsed

    assert::equal "${parsed[allocation_size_lo]}" "4096" "allocation basse lue"
    assert::equal "${parsed[end_of_file_lo]}" "1234" "EOF bas lu"
    assert::equal "${parsed[file_attributes]}" "32" "FileAttributes lus"
}
