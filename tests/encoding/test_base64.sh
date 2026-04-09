#!/usr/bin/env bash
#
# tests/encoding/test_base64.sh — Tests unitaires pour lib/encoding/base64.sh
#

ensh::import encoding/base64

test::base64_encode_hex() {
    local out

    # RFC 4648 §10 vecteurs de test
    base64::encode_hex "" out
    assert::empty "${out}" "encode hex vide"

    # "Man" = 4D 61 6E → TWFu
    base64::encode_hex "4D616E" out
    assert::equal "${out}" "TWFu" "encode 'Man'"

    # "Ma" = 4D 61 → TWE=
    base64::encode_hex "4D61" out
    assert::equal "${out}" "TWE=" "encode 'Ma' (padding 1)"

    # "M" = 4D → TQ==
    base64::encode_hex "4D" out
    assert::equal "${out}" "TQ==" "encode 'M' (padding 2)"

    # "Hello" = 48 65 6C 6C 6F → SGVsbG8=
    base64::encode_hex "48656C6C6F" out
    assert::equal "${out}" "SGVsbG8=" "encode 'Hello'"
}

test::base64_encode_string() {
    local out

    base64::encode_string "Man" out
    assert::equal "${out}" "TWFu" "encode_string 'Man'"

    base64::encode_string "" out
    assert::empty "${out}" "encode_string vide"

    base64::encode_string "Hello, World!" out
    assert::equal "${out}" "SGVsbG8sIFdvcmxkIQ==" "encode_string 'Hello, World!'"
}

test::base64_decode() {
    local out

    base64::decode "" out
    assert::empty "${out}" "decode vide"

    base64::decode "TWFu" out
    assert::equal "${out}" "4D616E" "decode 'TWFu' → 'Man'"

    base64::decode "TWE=" out
    assert::equal "${out}" "4D61" "decode 'TWE=' → 'Ma'"

    base64::decode "TQ==" out
    assert::equal "${out}" "4D" "decode 'TQ==' → 'M'"

    base64::decode "SGVsbG8=" out
    assert::equal "${out}" "48656C6C6F" "decode 'SGVsbG8=' → 'Hello'"
}

test::base64_roundtrip() {
    local encoded decoded

    base64::encode_hex "DEADBEEF" encoded
    base64::decode "${encoded}" decoded
    assert::equal "${decoded}" "DEADBEEF" "roundtrip hex DEADBEEF"

    base64::encode_string "Test123" encoded
    base64::decode "${encoded}" decoded
    # Test123 = 54657374313233
    assert::equal "${decoded}" "54657374313233" "roundtrip string Test123"
}
