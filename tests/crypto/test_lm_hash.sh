#!/usr/bin/env bash
#
# tests/crypto/test_lm_hash.sh — Tests unitaires pour lib/crypto/lm_hash.sh
#
# Vecteurs issus de MS-NLMP §4.2.2.1.1 et divers outils de référence.
#

ensh::import crypto/lm_hash

# DES-ECB est désactivé dans OpenSSL 3.0+ (mode legacy).
# On détecte sa disponibilité avant d'exécuter les tests qui en dépendent.
_lm_has_des_ecb() {
    printf '\x00\x00\x00\x00\x00\x00\x00\x00' \
        | openssl enc -des-ecb -nosalt -nopad -K "0000000000000000" 2>/dev/null \
        | xxd -p >/dev/null 2>&1
}

test::lm_hash_empty_password() {
    if ! _lm_has_des_ecb; then
        skip "DES-ECB non disponible (OpenSSL 3+ legacy provider absent)"
        return
    fi
    local out
    # LM hash du mot de passe vide = AAD3B435B51404EEAAD3B435B51404EE
    lm_hash::from_password "" out
    assert::equal "${out}" "AAD3B435B51404EEAAD3B435B51404EE" "LM hash mot de passe vide"
}

test::lm_hash_password() {
    if ! _lm_has_des_ecb; then
        skip "DES-ECB non disponible (OpenSSL 3+ legacy provider absent)"
        return
    fi
    local out
    # LM hash de "Password" = E52CAC67419A9A224A3B108F3FA6CB6D
    lm_hash::from_password "Password" out
    assert::equal "${out}" "E52CAC67419A9A224A3B108F3FA6CB6D" "LM hash 'Password'"
}

test::lm_hash_output_length() {
    if ! _lm_has_des_ecb; then
        skip "DES-ECB non disponible (OpenSSL 3+ legacy provider absent)"
        return
    fi
    local out
    lm_hash::from_password "test" out
    assert::length_equal "${out}" 16 "LM hash produit 16 octets"
}

test::lm_hash_case_insensitive() {
    local out_lower out_upper
    # LM hash est insensible à la casse (tout mis en majuscules)
    lm_hash::from_password "password" out_lower
    lm_hash::from_password "PASSWORD" out_upper
    assert::equal "${out_lower}" "${out_upper}" "LM hash insensible à la casse"
}

test::lm_hash_truncate_at_14() {
    local out_14 out_15
    # LM hash tronque à 14 caractères
    lm_hash::from_password "12345678901234" out_14
    lm_hash::from_password "123456789012345" out_15
    assert::equal "${out_14}" "${out_15}" "LM hash tronque à 14 chars"
}
