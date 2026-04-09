#!/usr/bin/env bash
#
# tests/crypto/test_md4.sh — Tests unitaires pour lib/crypto/md4.sh
#
# Vecteurs de test issus de la RFC 1320 §A.5.
#

ensh::import crypto/md4

test::md4_empty_string() {
    local out
    # MD4("") = 31D6CFE0D16AE931B73C59D7E0C089C0  (RFC 1320)
    md4::hash "" out
    assert::equal "${out}" "31D6CFE0D16AE931B73C59D7E0C089C0" "MD4 chaîne vide"
}

test::md4_single_a() {
    local out
    # MD4("a") = hex de "a" = 61
    # Résultat attendu : BDE52CB31DE33E46245E05FBDBD6FB24
    md4::hash "61" out
    assert::equal "${out}" "BDE52CB31DE33E46245E05FBDBD6FB24" "MD4('a')"
}

test::md4_abc() {
    local out
    # MD4("abc") = hex de "abc" = 616263
    # Résultat attendu : A448017AAF21D8525FC10AE87AA6729D
    md4::hash "616263" out
    assert::equal "${out}" "A448017AAF21D8525FC10AE87AA6729D" "MD4('abc')"
}

test::md4_message_digest() {
    local out
    # MD4("message digest") = hex = 6D65737361676520646967657374
    # Résultat attendu : D9130A8164549FE818874806E1C7014B
    local msg_hex
    hex::from_string "message digest" msg_hex
    md4::hash "${msg_hex}" out
    assert::equal "${out}" "D9130A8164549FE818874806E1C7014B" "MD4('message digest')"
}

test::md4_output_length() {
    local out
    md4::hash "" out
    assert::length_equal "${out}" 16 "MD4 produit 16 octets"
}

test::md4_deterministic() {
    local out1 out2
    md4::hash "DEADBEEF" out1
    md4::hash "DEADBEEF" out2
    assert::equal "${out1}" "${out2}" "MD4 déterministe"
}
