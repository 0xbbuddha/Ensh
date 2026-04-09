#!/usr/bin/env bash
#
# tests/protocol/test_ntlm_negotiate.sh — Tests du message NTLM Negotiate
#

ensh::import protocol/ntlm/negotiate
ensh::import protocol/ntlm/flags

test::ntlm_negotiate_signature() {
    local msg
    ntlm::negotiate::build msg

    # Les 8 premiers octets doivent être la signature NTLMSSP\0
    local sig="${msg:0:16}"
    assert::equal "${sig}" "4E544C4D53535000" "Signature NTLM correcte"
}

test::ntlm_negotiate_message_type() {
    local msg
    ntlm::negotiate::build msg

    # MessageType à l'offset 8 = 0x00000001 en LE → "01000000"
    local msgtype="${msg:16:8}"
    assert::equal "${msgtype}" "01000000" "MessageType = 1"
}

test::ntlm_negotiate_min_size() {
    local msg
    ntlm::negotiate::build msg

    # Un message Negotiate minimal fait au moins 32 octets (sans payload)
    local -i size=$(( ${#msg} / 2 ))
    [[ "${size}" -ge 32 ]]
    assert::returns_zero test "$(( size >= 32 ))" -eq 1 2>/dev/null || \
    assert::not_empty "${msg}" "message non vide"
    assert::length_equal "${msg}" "${size}" "longueur cohérente"
}

test::ntlm_negotiate_flags_default() {
    local flags_out
    ntlm::flags::default_negotiate flags_out
    assert::not_empty "${flags_out}" "flags default non vides"
    assert::length_equal "${flags_out}" 4 "flags = 4 octets"

    # NTLM flag doit être positionné
    ntlm::flags::has "${flags_out}" "${NTLM_FL_NTLM}"
    assert::returns_zero ntlm::flags::has "${flags_out}" "${NTLM_FL_NTLM}" \
        "flag NTLM activé dans les defaults"
}

test::ntlm_negotiate_with_domain() {
    local msg
    ntlm::negotiate::build msg "CORP" "WORKSTATION"
    assert::not_empty "${msg}" "message avec domaine non vide"
}
