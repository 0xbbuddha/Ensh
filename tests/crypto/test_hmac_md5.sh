#!/usr/bin/env bash
#
# tests/crypto/test_hmac_md5.sh — Tests unitaires pour HMAC-MD5
#
# Vecteurs de test issus de la RFC 2202.
#

ensh::import crypto/hmac_md5

# ── RFC 2202 Test Vectors ─────────────────────────────────────────────────────

test::hmac_md5_rfc2202_case1() {
    # Clé  : 0x0b * 16
    # Data : "Hi There"
    # HMAC : 9294727A3811050D00FD5BA89B7A86AE
    if ! command -v openssl >/dev/null 2>&1; then
        skip "openssl non disponible"
        return
    fi

    local key msg out
    bytes::repeat "0B" 16 key 2>/dev/null || {
        local i; key=""
        for (( i=0; i<16; i++ )); do key+="0B"; done
    }
    hex::from_string "Hi There" msg

    hmac_md5::compute "${key}" "${msg}" out
    # Vérifié par Python hmac.new(key, b"Hi There", hashlib.md5).hexdigest()
    assert::equal "${out^^}" "9294727A3638BB1C13F48EF8158BFC9D" \
        "HMAC-MD5 RFC 2202 cas 1"
}

test::hmac_md5_rfc2202_case2() {
    # Clé  : "Jefe"
    # Data : "what do ya want for nothing?"
    # HMAC : 750C783E6AB0B503EAA86E310A5DB738
    if ! command -v openssl >/dev/null 2>&1; then
        skip "openssl non disponible"
        return
    fi

    local key msg out
    hex::from_string "Jefe" key
    hex::from_string "what do ya want for nothing?" msg

    hmac_md5::compute "${key}" "${msg}" out
    assert::equal "${out^^}" "750C783E6AB0B503EAA86E310A5DB738" \
        "HMAC-MD5 RFC 2202 cas 2"
}

test::hmac_md5_output_length() {
    if ! command -v openssl >/dev/null 2>&1; then
        skip "openssl non disponible"
        return
    fi

    local key msg out
    hex::from_string "key" key
    hex::from_string "message" msg
    hmac_md5::compute "${key}" "${msg}" out
    assert::length_equal "${out}" 16 "HMAC-MD5 = 16 octets"
}
