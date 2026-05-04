#!/usr/bin/env bash
#
# tests/crypto/test_ntlmv1.sh — Tests NTLMv1 Response
#
# Vecteurs de test :
#   Password = "Password"
#   NT hash  = A4F49C406510BDCAB6824EE7C30FD852
#   Challenge = 0102030405060708
#   NTLMv1 response attendu = 59C7BD29D7987ACA8405C51DF31C1E15B107F53CC162BACA
#
# Référence : MS-NLMP §3.3.1
#

ensh::import crypto/ntlmv1

readonly _NTV1_NT_HASH="A4F49C406510BDCAB6824EE7C30FD852"
readonly _NTV1_CHALLENGE="0102030405060708"
readonly _NTV1_EXPECTED="59C7BD29D7987ACA8405C51DF31C1E15B107F53CC162BACA"

# ── DES key expansion ─────────────────────────────────────────────────────────

test::ntlmv1_des_key_expansion() {
    # 7 premiers octets du NT hash paddé : A4F49C406510BD
    local key
    _ntlmv1_des_key "A4F49C406510BD" key
    assert::equal "${key}" "A47A26880628427A" "expansion clé DES #1"
}

# ── NTLMv1 Response ───────────────────────────────────────────────────────────

test::ntlmv1_response_length() {
    local resp
    ntlmv1::response resp "${_NTV1_NT_HASH}" "${_NTV1_CHALLENGE}" || return 0
    assert::length_equal "${resp}" 24 "NTLMv1 response = 24 octets"
}

test::ntlmv1_response_value() {
    local resp
    ntlmv1::response resp "${_NTV1_NT_HASH}" "${_NTV1_CHALLENGE}" || {
        assert::skip "ntlmv1::response : openssl-legacy non disponible"
        return 0
    }
    assert::equal "${resp^^}" "${_NTV1_EXPECTED}" "NTLMv1 response (Password, challenge fixe)"
}

test::ntlmv1_compute_matches_response() {
    local nt_resp lm_resp
    ntlmv1::compute nt_resp lm_resp "Password" "${_NTV1_CHALLENGE}" || {
        assert::skip "ntlmv1::compute : openssl-legacy non disponible"
        return 0
    }
    assert::equal "${nt_resp^^}" "${_NTV1_EXPECTED}" "compute NT response = response directe"
    assert::length_equal "${lm_resp}" 24 "LM response = 24 octets"
}

# ── Format hashcat ────────────────────────────────────────────────────────────

test::ntlmv1_format_hashcat() {
    local line
    line=$(ntlmv1::format_hashcat "alice" "CORP" \
        "${_NTV1_CHALLENGE}" \
        "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011" \
        "${_NTV1_EXPECTED}")

    local expected="alice::CORP:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011:${_NTV1_EXPECTED}:${_NTV1_CHALLENGE}"
    assert::equal "${line}" "${expected}" "format hashcat 5500"
}
