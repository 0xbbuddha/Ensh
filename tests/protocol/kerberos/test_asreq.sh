#!/usr/bin/env bash
#
# tests/protocol/kerberos/test_asreq.sh — Tests Kerberos AS-REQ / AS-REP
#

ensh::import protocol/kerberos/asreq

test::kerberos_asreq_build_without_preauth() {
    local req
    kerberos::asreq::build req "alice" "pirate.htb"

    local expected="6A819A308197A103020105A20302010AA4818A308187A00703050050800000"
    expected+="A1123010A003020101A10930071B05616C696365"
    expected+="A20C1B0A5049524154452E485442"
    expected+="A31F301DA003020101A11630141B066B72627467741B0A5049524154452E485442"
    expected+="A511180F32303337303931333032343830355A"
    expected+="A611180F32303337303931333032343830355A"
    expected+="A706020412345678"
    expected+="A80B3009020117020112020111"

    assert::equal "${req}" "${expected}" "AS-REQ sans pré-auth doit matcher le DER de référence"
}

test::kerberos_asreq_build_with_preauth_blob() {
    local req
    kerberos::asreq::build req "alice" "pirate.htb" "300DA003020117A2060404A1B2C3D4"

    local expected="6A81B83081B5A103020105A20302010A"
    expected+="A31C301A3018A103020102A211040F300DA003020117A2060404A1B2C3D4"
    expected+="A4818A308187A00703050050800000"
    expected+="A1123010A003020101A10930071B05616C696365"
    expected+="A20C1B0A5049524154452E485442"
    expected+="A31F301DA003020101A11630141B066B72627467741B0A5049524154452E485442"
    expected+="A511180F32303337303931333032343830355A"
    expected+="A611180F32303337303931333032343830355A"
    expected+="A706020412345678"
    expected+="A80B3009020117020112020111"

    assert::equal "${req}" "${expected}" "AS-REQ avec PA-ENC-TIMESTAMP doit matcher le DER de référence"
}

test::kerberos_asreq_parse_asrep() {
    local asrep="6B81A53081A2A003020105A10302010BA30C1B0A5049524154452E485442"
    asrep+="A4123010A003020101A10930071B05616C696365"
    asrep+="A5526150304EA003020105A10C1B0A5049524154452E485442"
    asrep+="A21F301DA003020102A11630141B066B72627467741B0A5049524154452E485442"
    asrep+="A3183016A003020117A103020102A20A040801020304AABBCCDD"
    asrep+="A620301EA003020117A103020103A212041011223344556677889900AABBCCDDEEFF"

    declare -A parsed=()
    kerberos::asreq::parse_asrep "${asrep}" parsed

    assert::equal "${parsed[realm]}" "PIRATE.HTB" "realm lu depuis l'AS-REP"
    assert::equal "${parsed[cname]}" "alice" "cname lu depuis l'AS-REP"
    assert::equal "${parsed[enc_etype]}" "23" "etype du enc-part"
    assert::equal "${parsed[enc_kvno]}" "3" "kvno du enc-part"
    assert::equal "${parsed[enc_cipher]}" "11223344556677889900AABBCCDDEEFF" "cipher du enc-part"
}

test::kerberos_asreq_parse_krberror() {
    local krberr="7E6E306CA003020105A10302011E"
    krberr+="A411180F32303236303431383132303030305A"
    krberr+="A505020301E240"
    krberr+="A603020119"
    krberr+="A90C1B0A5049524154452E485442"
    krberr+="AA1F301DA003020102A11630141B066B72627467741B0A5049524154452E485442"
    krberr+="AB121B10505245415554485F5245515549524544"

    declare -A parsed=()
    kerberos::asreq::parse_krberror "${krberr}" parsed

    assert::equal "${parsed[error_code]}" "25" "error-code lu depuis le KRB-ERROR"
    assert::equal "${parsed[error_name]}" "KDC_ERR_PREAUTH_REQUIRED" "nom du code erreur"
    assert::equal "${parsed[realm]}" "PIRATE.HTB" "realm serveur lu"
    assert::equal "${parsed[e_text]}" "PREAUTH_REQUIRED" "texte d'erreur lu"
}
