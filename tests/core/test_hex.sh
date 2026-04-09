#!/usr/bin/env bash
#
# tests/core/test_hex.sh — Tests unitaires pour lib/core/hex.sh
#

ensh::import core/hex

test::hex_from_string() {
    local out
    hex::from_string "AB" out
    assert::equal "${out}" "4142" "from_string 'AB'"

    hex::from_string "" out
    assert::empty "${out}" "from_string vide"

    hex::from_string "Hello" out
    assert::equal "${out}" "48656C6C6F" "from_string 'Hello'"
}

test::hex_to_string() {
    local out
    hex::to_string "4142" out
    assert::equal "${out}" "AB" "to_string '4142'"

    hex::to_string "48656C6C6F" out
    assert::equal "${out}" "Hello" "to_string 'Hello'"
}

test::hex_from_int() {
    local out
    hex::from_int 256 2 out
    assert::equal "${out}" "0100" "from_int 256 sur 2 octets (BE)"

    hex::from_int 0 4 out
    assert::equal "${out}" "00000000" "from_int 0 sur 4 octets"

    hex::from_int 255 1 out
    assert::equal "${out}" "FF" "from_int 255 sur 1 octet"
}

test::hex_to_int() {
    local out
    hex::to_int "0100" out
    assert::equal "${out}" "256" "to_int '0100'"

    hex::to_int "FF" out
    assert::equal "${out}" "255" "to_int 'FF'"
}

test::hex_concat() {
    local out
    hex::concat out "AABB" "CCDD"
    assert::equal "${out}" "AABBCCDD" "concat"
}

test::hex_slice() {
    local out
    hex::slice "AABBCCDD" 1 2 out
    assert::equal "${out}" "BBCC" "slice offset=1, len=2"

    hex::slice "AABBCCDD" 0 4 out
    assert::equal "${out}" "AABBCCDD" "slice complet"
}

test::hex_xor() {
    local out
    hex::xor "FF" "0F" out
    assert::equal "${out}" "F0" "xor FF ^ 0F"

    hex::xor "AABB" "5566" out
    assert::equal "${out}" "FFDD" "xor AABB ^ 5566"
}

test::hex_pad_right() {
    local out
    hex::pad_right "AABB" 4 out
    assert::equal "${out}" "AABB0000" "pad_right à 4 octets"
}

test::hex_pad_left() {
    local out
    hex::pad_left "AABB" 4 out
    assert::equal "${out}" "0000AABB" "pad_left à 4 octets"
}

test::hex_is_valid() {
    assert::returns_zero hex::is_valid "DEADBEEF"
    assert::returns_zero hex::is_valid "00"
    assert::returns_zero hex::is_valid ""
}

test::hex_length() {
    local out
    hex::length "AABBCCDD" out
    assert::equal "${out}" "4" "length de 4 octets"

    hex::length "" out
    assert::equal "${out}" "0" "length de chaîne vide"
}
