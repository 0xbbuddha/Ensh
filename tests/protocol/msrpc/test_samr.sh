#!/usr/bin/env bash
#
# tests/protocol/msrpc/test_samr.sh — Tests SAMR / NDR
#

ensh::import protocol/msrpc/samr

test::samr_encode_ustr_ptr_lookup_domain() {
    local hdr def
    _SAMR_REF_ID=0x00020000
    _samr_encode_ustr_ptr hdr def "pirate"

    assert::equal "${hdr}" "0C000C0000000200" \
        "RPC_UNICODE_STRING inline doit exposer Length/MaximumLength sans NUL implicite"
    assert::equal "${def}" "060000000000000006000000700069007200610074006500" \
        "buffer déféré doit contenir uniquement les 6 caractères UTF-16LE"
}

test::samr_encode_sid_domain_sid() {
    local sid
    _samr_encode_sid sid "0104000000000005150000008051D2F4F551D7F78063814D"

    assert::equal "${sid}" "040000000104000000000005150000008051D2F4F551D7F78063814D" \
        "RPC_SID doit être encodé comme MaxCount + SID brut"
}
