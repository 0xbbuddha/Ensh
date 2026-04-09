#!/usr/bin/env bash
#
# tests/core/test_endian.sh — Tests unitaires pour lib/core/endian.sh
#

ensh::import core/endian

test::endian_le16() {
    local out
    endian::le16 0x1234 out
    assert::equal "${out}" "3412" "le16 0x1234 → 3412"

    endian::le16 0 out
    assert::equal "${out}" "0000" "le16 0"

    endian::le16 0xFFFF out
    assert::equal "${out}" "FFFF" "le16 0xFFFF"
}

test::endian_le32() {
    local out
    endian::le32 0x12345678 out
    assert::equal "${out}" "78563412" "le32 0x12345678"

    endian::le32 1 out
    assert::equal "${out}" "01000000" "le32 1"
}

test::endian_be16() {
    local out
    endian::be16 0x1234 out
    assert::equal "${out}" "1234" "be16 0x1234"
}

test::endian_be32() {
    local out
    endian::be32 0x12345678 out
    assert::equal "${out}" "12345678" "be32 0x12345678"
}

test::endian_read_le16() {
    local out
    # "3412" en mémoire = 0x1234 en LE
    endian::read_le16 "3412" 0 out
    assert::equal "${out}" "4660" "read_le16 '3412' → 0x1234 = 4660"
}

test::endian_read_le32() {
    local out
    endian::read_le32 "78563412" 0 out
    assert::equal "${out}" "305419896" "read_le32 '78563412' → 0x12345678 = 305419896"
}

test::endian_swap() {
    local out
    endian::swap "01020304" out
    assert::equal "${out}" "04030201" "swap 4 octets"

    endian::swap "AABB" out
    assert::equal "${out}" "BBAA" "swap 2 octets"
}

test::endian_roundtrip_le32() {
    local encoded decoded
    endian::le32 12345 encoded
    endian::read_le32 "${encoded}" 0 decoded
    assert::equal "${decoded}" "12345" "roundtrip le32 : 12345"
}
