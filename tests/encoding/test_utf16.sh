#!/usr/bin/env bash
#
# tests/encoding/test_utf16.sh — Tests unitaires pour lib/encoding/utf16.sh
#

ensh::import encoding/utf16

test::utf16_encode_le() {
    local out

    utf16::encode_le "AB" out
    assert::equal "${out}" "41004200" "encode_le 'AB'"

    utf16::encode_le "" out
    assert::empty "${out}" "encode_le vide"

    # 'A' = U+0041, 'Z' = U+005A
    utf16::encode_le "AZ" out
    assert::equal "${out}" "41005A00" "encode_le 'AZ'"

    # Cas important pour NTLM : le nom de domaine en UTF-16LE
    utf16::encode_le "CORP" out
    assert::equal "${out}" "43004F0052005000" "encode_le 'CORP'"
}

test::utf16_encode_be() {
    local out

    utf16::encode_be "AB" out
    assert::equal "${out}" "00410042" "encode_be 'AB'"

    utf16::encode_be "" out
    assert::empty "${out}" "encode_be vide"

    utf16::encode_be "AZ" out
    assert::equal "${out}" "0041005A" "encode_be 'AZ'"
}

test::utf16_decode_le() {
    local out

    utf16::decode_le "41004200" out
    assert::equal "${out}" "AB" "decode_le '41004200' → 'AB'"

    utf16::decode_le "" out
    assert::empty "${out}" "decode_le vide"

    utf16::decode_le "43004F0052005000" out
    assert::equal "${out}" "CORP" "decode_le 'CORP'"
}

test::utf16_decode_be() {
    local out

    utf16::decode_be "00410042" out
    assert::equal "${out}" "AB" "decode_be '00410042' → 'AB'"

    utf16::decode_be "" out
    assert::empty "${out}" "decode_be vide"
}

test::utf16_roundtrip_le() {
    local encoded decoded

    utf16::encode_le "Hello" encoded
    utf16::decode_le "${encoded}" decoded
    assert::equal "${decoded}" "Hello" "roundtrip LE 'Hello'"

    utf16::encode_le "DOMAIN" encoded
    utf16::decode_le "${encoded}" decoded
    assert::equal "${decoded}" "DOMAIN" "roundtrip LE 'DOMAIN'"
}

test::utf16_roundtrip_be() {
    local encoded decoded

    utf16::encode_be "World" encoded
    utf16::decode_be "${encoded}" decoded
    assert::equal "${decoded}" "World" "roundtrip BE 'World'"
}

test::utf16_uppercase_le() {
    local out

    # Encoder "corp", mettre en majuscules en UTF-16LE → "CORP"
    local encoded
    utf16::encode_le "corp" encoded
    utf16::uppercase_le "${encoded}" out
    local decoded
    utf16::decode_le "${out}" decoded
    assert::equal "${decoded}" "CORP" "uppercase_le 'corp' → 'CORP'"
}
