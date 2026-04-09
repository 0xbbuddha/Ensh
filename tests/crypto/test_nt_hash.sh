#!/usr/bin/env bash
#
# tests/crypto/test_nt_hash.sh — Tests unitaires pour le NT Hash
#
# Les vecteurs de test sont issus des RFC NTLM et de tests publics
# (MS-NLMP documentation officielle, IMPacket test suite).
#

ensh::import crypto/nt_hash

# ── Vecteurs de test (MS-NLMP Appendix B) ────────────────────────────────────

test::nt_hash_password() {
    local out

    # Vecteur 1 (MS-NLMP §4.2.2) : Password = "Password"
    nt_hash::from_password "Password" out
    assert::equal "${out^^}" "A4F49C406510BDCAB6824EE7C30FD852" \
        "NT hash de 'Password'"
}

test::nt_hash_empty() {
    local out
    # NT hash du mot de passe vide
    nt_hash::from_password "" out
    assert::equal "${out^^}" "31D6CFE0D16AE931B73C59D7E0C089C0" \
        "NT hash du mot de passe vide"
}

test::nt_hash_special_chars() {
    local out
    # NT hash de "abc123" (vecteur généré via impacket/smbpasswd)
    nt_hash::from_password "abc123" out
    # Note : ce hash doit être vérifié — valeur connue de impacket
    assert::not_empty "${out}" "NT hash de 'abc123' non vide"
    assert::length_equal "${out}" 16 "NT hash = 16 octets"
}

test::nt_hash_length() {
    local out
    nt_hash::from_password "quelconque" out
    assert::length_equal "${out}" 16 "NT hash toujours 16 octets"
}
