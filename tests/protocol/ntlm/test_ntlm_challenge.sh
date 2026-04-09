#!/usr/bin/env bash
#
# tests/protocol/ntlm/test_ntlm_challenge.sh — Tests pour ntlm/challenge.sh
#
# Le message Challenge est fabriqué à la main pour les tests unitaires
# sans dépendance réseau.
#

ensh::import protocol/ntlm/challenge
ensh::import protocol/ntlm/flags

# ── Fabrication d'un Challenge de test ───────────────────────────────────────
#
# Structure minimale d'un NTLM Challenge (56 octets fixes + payload) :
#   Offset  0 : Signature "NTLMSSP\0"        (8 octets)
#   Offset  8 : MessageType = 2              (4 octets LE)
#   Offset 12 : TargetNameFields             (8 octets : Len, MaxLen, Offset)
#   Offset 20 : NegotiateFlags               (4 octets LE)
#   Offset 24 : ServerChallenge              (8 octets)
#   Offset 32 : Reserved                     (8 octets = 00)
#   Offset 40 : TargetInfoFields             (8 octets : Len, MaxLen, Offset)
#   Offset 48 : Version                      (8 octets, optionnel)
#   Offset 56 : Payload (TargetName + TargetInfo)

_build_test_challenge() {
    local -n _btc_out="$1"

    local sig="4E544C4D53535000"          # "NTLMSSP\0"
    local msgtype="02000000"               # Type 2

    # TargetName = "TEST" en UTF-16LE = 54005400450053005400 (5 chars × 2 = 10 octets)
    # Mais ici: "DOM" en UTF-16LE = 440 04F004D00 (3 × 2 = 6 octets)
    local target_name="44004F004D00"       # "DOM" UTF-16LE (6 octets)
    local tn_len; endian::le16 6 tn_len
    local tn_maxlen="${tn_len}"
    # TargetName sera à l'offset 56 (après header fixe de 56 octets)
    local tn_off; endian::le32 56 tn_off

    local tn_fields="${tn_len}${tn_maxlen}${tn_off}"   # 8 octets

    # Flags = UNICODE | NTLM | REQUEST_TARGET (pour le test)
    local flags_int=$(( NTLM_FL_UNICODE | NTLM_FL_NTLM | NTLM_FL_REQUEST_TARGET ))
    local flags; ntlm::flags::to_le32 "${flags_int}" flags

    # ServerChallenge = 0102030405060708
    local server_challenge="0102030405060708"

    local reserved="0000000000000000"

    # TargetInfo minimal : NbDomain="DOM" en UTF-16LE (6 octets) + EOL
    # AvId=0002 (NbDomain), AvLen=6, Val=44004F004D00
    local avpair_domain; endian::le16 2 avid_le; endian::le16 6 avlen_le
    local ti_data="${avid_le}${avlen_le}44004F004D00"
    # EOL AvPair
    ti_data+="00000000"
    local ti_len=$(( ${#ti_data} / 2 ))

    local ti_len_le; endian::le16 "${ti_len}" ti_len_le
    local ti_off_val=$(( 56 + ${#target_name}/2 ))
    local ti_off_le; endian::le32 "${ti_off_val}" ti_off_le

    local ti_fields="${ti_len_le}${ti_len_le}${ti_off_le}"   # 8 octets

    # Version (8 octets de zéros)
    local version="0000000000000000"

    _btc_out="${sig}${msgtype}${tn_fields}${flags}${server_challenge}${reserved}${ti_fields}${version}${target_name}${ti_data}"
}

test::ntlm_challenge_parse_signature() {
    local chall
    _build_test_challenge chall

    declare -A parsed=()
    ntlm::challenge::parse "${chall}" parsed

    assert::equal "${parsed[server_challenge]}" "0102030405060708" "server_challenge extrait"
    assert::not_empty "${parsed[flags]}"        "flags présents"
    assert::not_empty "${parsed[target_name]}"  "target_name présent"
}

test::ntlm_challenge_flags_parsed() {
    local chall
    _build_test_challenge chall

    declare -A parsed=()
    ntlm::challenge::parse "${chall}" parsed

    assert::returns_zero ntlm::flags::has "${parsed[flags]}" "${NTLM_FL_UNICODE}" "flag UNICODE présent"
    assert::returns_zero ntlm::flags::has "${parsed[flags]}" "${NTLM_FL_NTLM}"    "flag NTLM présent"
}

test::ntlm_challenge_invalid_signature() {
    # Un message avec mauvaise signature doit échouer
    local fake="0000000000000000020000000000000000000000"
    declare -A parsed=()
    if ntlm::challenge::parse "${fake}" parsed 2>/dev/null; then
        # Ne devrait pas réussir
        (( _TEST_FAILED++ ))
        _TEST_FAILURES+=( "  ÉCHEC : challenge invalide accepté" )
    else
        (( _TEST_TOTAL++ ))
        (( _TEST_PASSED++ ))
    fi
}

test::ntlm_challenge_build_target_info() {
    local ti
    ntlm::challenge::build_target_info ti "DOMAIN" "SERVER" "domain.local" "srv.domain.local"

    assert::not_empty "${ti}" "TargetInfo non vide"

    # Doit se terminer par EOL (00000000)
    local eol="${ti: -8}"
    assert::equal "${eol}" "00000000" "TargetInfo se termine par EOL"
}

test::ntlm_challenge_parse_target_info() {
    local ti
    ntlm::challenge::build_target_info ti "CORP" "SRV01"

    declare -A ti_dict=()
    ntlm::challenge::parse_target_info "${ti}" ti_dict

    assert::not_empty "${ti_dict[nb_domain]:-}"   "nb_domain présent"
    assert::not_empty "${ti_dict[nb_computer]:-}" "nb_computer présent"
}
