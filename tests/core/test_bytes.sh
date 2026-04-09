#!/usr/bin/env bash
#
# tests/core/test_bytes.sh — Tests unitaires pour lib/core/bytes.sh
#

ensh::import core/bytes

test::bytes_new() {
    local buf
    bytes::new buf
    assert::empty "${buf}" "buffer initialisé vide"
}

test::bytes_append_prepend() {
    local buf
    bytes::new buf
    bytes::append buf "AABB"
    assert::equal "${buf}" "AABB" "append une fois"

    bytes::append buf "CCDD"
    assert::equal "${buf}" "AABBCCDD" "append deux fois"

    bytes::prepend buf "0011"
    assert::equal "${buf}" "0011AABBCCDD" "prepend"
}

test::bytes_write_at() {
    local buf="AABBCCDD"
    bytes::write_at buf 1 "1234"
    assert::equal "${buf}" "AA1234DD" "write_at offset=1, 2 octets"

    local buf2="0000000000"
    bytes::write_at buf2 0 "FFFF"
    assert::equal "${buf2}" "FFFF000000" "write_at offset=0"
}

test::bytes_read() {
    local out
    bytes::read "AABBCCDD" 1 2 out
    assert::equal "${out}" "BBCC" "read offset=1, len=2"

    bytes::read "AABBCCDD" 0 4 out
    assert::equal "${out}" "AABBCCDD" "read complet"
}

test::bytes_read_integers() {
    local out
    bytes::read_u8 "AABBCC" 1 out
    assert::equal "${out}" "187" "read_u8 (0xBB = 187)"

    bytes::read_le16 "0100AABB" 0 out
    assert::equal "${out}" "1" "read_le16 : 0x0001 = 1"

    bytes::read_le32 "01000000AABB" 0 out
    assert::equal "${out}" "1" "read_le32 : 0x00000001 = 1"

    bytes::read_be16 "0100AABB" 0 out
    assert::equal "${out}" "256" "read_be16 : 0x0100 = 256"
}

test::bytes_field_serializers() {
    local out
    bytes::field_u8 65 out
    assert::equal "${out}" "41" "field_u8 65 → 0x41"

    bytes::field_le16 256 out
    assert::equal "${out}" "0001" "field_le16 256 → 0001 LE"

    bytes::field_le32 1 out
    assert::equal "${out}" "01000000" "field_le32 1 → 01000000 LE"

    bytes::field_be16 256 out
    assert::equal "${out}" "0100" "field_be16 256 → 0100 BE"
}

test::bytes_size() {
    local out
    bytes::size "AABBCCDD" out
    assert::equal "${out}" "4" "size de 4 octets"

    bytes::size "" out
    assert::equal "${out}" "0" "size vide"
}

test::bytes_zero() {
    local out
    bytes::zero 4 out
    assert::equal "${out}" "00000000" "zero 4 octets"

    bytes::zero 0 out
    assert::empty "${out}" "zero 0 octets"
}

test::bytes_repeat() {
    local out
    bytes::repeat "FF" 4 out
    assert::equal "${out}" "FFFFFFFF" "repeat FF × 4"

    bytes::repeat "AB" 1 out
    assert::equal "${out}" "AB" "repeat AB × 1"

    bytes::repeat "00" 3 out
    assert::equal "${out}" "000000" "repeat 00 × 3"
}
