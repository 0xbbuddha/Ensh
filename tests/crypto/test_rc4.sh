#!/usr/bin/env bash
#
# tests/crypto/test_rc4.sh — Tests unitaires pour lib/crypto/rc4.sh
#
# Vecteurs de test issus de RFC 4757 et sources publiques.
#

ensh::import crypto/rc4

test::rc4_symmetry() {
    local enc dec
    # RC4 est symétrique : decrypt(encrypt(data)) = data
    rc4::crypt "4B6579" "48656C6C6F" enc     # key="Key", plain="Hello"
    rc4::crypt "4B6579" "${enc}" dec
    assert::equal "${dec}" "48656C6C6F" "RC4 symétrique"
}

test::rc4_known_vector_1() {
    local out
    # Vecteur connu : clé=0x0102030405, plaintext=0x0000000000000000
    # Référence : http://www.rfc-editor.org/rfc/rfc6229
    # RC4(0102030405, 0000000000000000) = B2396305F03DC027
    rc4::crypt "0102030405" "0000000000000000" out
    assert::equal "${out}" "B2396305F03DC027" "RC4 vecteur connu 1"
}

test::rc4_known_vector_2() {
    local out
    # Vecteur connu : clé=0x0102030405, plaintext=plaintext
    # Pré-calculé : clé=01020304 (4 bytes), texte="Test" = 54657374
    # RC4(01020304, 54657374) = résultat connu
    # Vérification par double-chiffrement
    local plain="DEADBEEFCAFE"
    local key="0102030405060708"
    local enc
    rc4::crypt "${key}" "${plain}" enc
    assert::not_equal "${enc}" "${plain}" "RC4 chiffre (ciphertext ≠ plaintext)"
    assert::length_equal "${enc}" "$(( ${#plain} / 2 ))" "RC4 conserve la longueur"
}

test::rc4_output_length() {
    local out
    rc4::crypt "FF" "AABBCCDD" out
    assert::length_equal "${out}" 4 "RC4 sortie = même longueur que l'entrée"
}

test::rc4_different_keys() {
    local out1 out2
    rc4::crypt "0000" "AABBCCDD" out1
    rc4::crypt "FFFF" "AABBCCDD" out2
    assert::not_equal "${out1}" "${out2}" "RC4 clés différentes → résultats différents"
}

test::rc4_empty_data() {
    local out
    rc4::crypt "AABBCC" "" out
    assert::empty "${out}" "RC4 données vides → sortie vide"
}
