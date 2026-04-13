#!/usr/bin/env bash
#
# tests/protocol/ntlm/test_ntlm_flags.sh — Tests pour lib/protocol/ntlm/flags.sh
#

ensh::import protocol/ntlm/flags

test::ntlm_flags_to_le32() {
    local out
    # 0x00000001 en LE32 = "01000000"
    ntlm::flags::to_le32 1 out
    assert::equal "${out}" "01000000" "flags 1 → LE32"

    # 0x00000200 (NTLM_FL_NTLM) en LE32 = "00020000"
    ntlm::flags::to_le32 "${NTLM_FL_NTLM}" out
    assert::equal "${out}" "00020000" "NTLM_FL_NTLM → LE32"
}

test::ntlm_flags_from_le32() {
    local out
    ntlm::flags::from_le32 "01000000" out
    assert::equal "${out}" "1" "LE32 '01000000' → 1"

    ntlm::flags::from_le32 "00020000" out
    assert::equal "${out}" "512" "LE32 '00020000' → 512 (0x200)"
}

test::ntlm_flags_roundtrip() {
    local le32 back
    ntlm::flags::to_le32 "${NTLM_FL_UNICODE}" le32
    ntlm::flags::from_le32 "${le32}" back
    assert::equal "${back}" "${NTLM_FL_UNICODE}" "roundtrip UNICODE flag"
}

test::ntlm_flags_has() {
    local flags_le32
    ntlm::flags::to_le32 "$(( NTLM_FL_UNICODE | NTLM_FL_NTLM ))" flags_le32

    assert::returns_zero ntlm::flags::has "${flags_le32}" "${NTLM_FL_UNICODE}" "has UNICODE → true"
    assert::returns_zero ntlm::flags::has "${flags_le32}" "${NTLM_FL_NTLM}"    "has NTLM → true"
}

test::ntlm_flags_set_clear() {
    local flags
    ntlm::flags::to_le32 0 flags

    ntlm::flags::set flags "${NTLM_FL_UNICODE}"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_UNICODE}" "set active le flag"

    ntlm::flags::clear flags "${NTLM_FL_UNICODE}"
    local val
    ntlm::flags::from_le32 "${flags}" val
    assert::equal "${val}" "0" "clear désactive le flag"
}

test::ntlm_flags_default_negotiate() {
    local flags
    ntlm::flags::default_negotiate flags

    assert::not_empty "${flags}" "default_negotiate non vide"
    assert::length_equal "${flags}" 4 "default_negotiate = 4 octets LE32"

    # Les flags essentiels doivent être présents
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_UNICODE}"           "default contient UNICODE"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_NTLM}"              "default contient NTLM"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_EXTENDED_SESS_SEC}" "default contient EXTENDED_SESS_SEC"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_128BIT}"            "default contient 128BIT"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_TARGET_INFO}"       "default contient TARGET_INFO"
}

test::ntlm_flags_type1_for_signing() {
    local flags
    ntlm::flags::type1_for_signing flags 1

    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_KEY_EXCH}"    "type1 signing contient KEY_EXCH"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_SIGN}"         "type1 signing contient SIGN"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_SEAL}"         "type1 signing contient SEAL"
    assert::returns_zero ntlm::flags::has "${flags}" "${NTLM_FL_ALWAYS_SIGN}"  "type1 signing contient ALWAYS_SIGN"
}

test::ntlm_flags_type3_from_challenge() {
    local type1="358288E0"      # impacket getNTLMSSPType1(..., signingRequired=True)
    local chall="058289E2"
    local out

    ntlm::flags::type3_from_challenge "${type1}" "${chall}" out
    assert::equal "${out}" "058288E0" "type3 flags alignés sur impacket"
}
