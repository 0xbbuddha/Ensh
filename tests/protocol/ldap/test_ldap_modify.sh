#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_modify.sh — Tests ModifyRequest / ModifyResponse
#

ensh::import protocol/ldap/modify

test::ldap_modify_build_replace_request() {
    local msg
    ldap::modify::build msg 1 "cn=alice,dc=test,dc=local" 2 "description" "hello"

    local expected="303F020101663A0419636E3D616C6963652C64633D746573742C64633D6C6F63616C"
    expected+="301D301B0A01023016040B6465736372697074696F6E3107040568656C6C6F"

    assert::equal "${msg}" "${expected}" "ModifyRequest replace doit matcher le BER de référence"
}

test::ldap_modify_build_delete_request_empty_values() {
    local msg
    ldap::modify::build msg 3 "cn=alice,dc=test,dc=local" delete "description"

    local expected="303802010366330419636E3D616C6963652C64633D746573742C64633D6C6F63616C"
    expected+="301630140A0101300F040B6465736372697074696F6E3100"

    assert::equal "${msg}" "${expected}" "ModifyRequest delete sans valeur doit produire un SET vide"
}

test::ldap_modify_build_add_multi_values() {
    local msg
    ldap::modify::build msg 3 "cn=alice,dc=test,dc=local" add "memberOf" "CN=Group1" "CN=Group2"

    local expected="304B02010366460419636E3D616C6963652C64633D746573742C64633D6C6F63616C"
    expected+="302930270A0100302204086D656D6265724F6631160409434E3D47726F7570310409434E3D47726F757032"

    assert::equal "${msg}" "${expected}" "ModifyRequest add multi-valeur doit rester ordonné"
}

test::ldap_modify_parse_response_success() {
    local resp="300C02010167070A010004000400"
    declare -A parsed=()
    ldap::modify::parse_response "${resp}" parsed

    assert::equal "${parsed[msg_id]}" "1" "message id lu"
    assert::equal "${parsed[op_tag]}" "67" "ModifyResponse attendu"
    assert::equal "${parsed[result_code]}" "0" "result code success"
    assert::equal "${parsed[result_name]}" "success" "nom du result code"
}

test::ldap_modify_parse_response_error() {
    local resp="302F020107672A0A0132041064633D746573742C64633D6C6F63616C0413696E73756666696369656E7420726967687473"
    declare -A parsed=()
    ldap::modify::parse_response "${resp}" parsed

    assert::equal "${parsed[result_code]}" "50" "result code access denied"
    assert::equal "${parsed[result_name]}" "insufficientAccessRights" "nom lisible du result code"
    assert::equal "${parsed[matched_dn]}" "dc=test,dc=local" "matchedDN lu"
    assert::equal "${parsed[diagnostic_msg]}" "insufficient rights" "diagnostic lu"
}

test::ldap_modify_encode_unicode_pwd() {
    local out
    ldap::modify::encode_unicode_pwd "P@ss" out
    assert::equal "${out}" "220050004000730073002200" "unicodePwd doit être encodé en UTF-16LE avec guillemets"
}

test::ldap_modify_build_hex_value() {
    local pwd_hex req
    ldap::modify::encode_unicode_pwd "P@ss" pwd_hex
    ldap::modify::build req 5 "cn=alice,dc=test,dc=local" replace "unicodePwd" "hex:${pwd_hex}"

    local found=0
    [[ "${req}" == *"040C220050004000730073002200"* ]] && found=1
    assert::equal "${found}" "1" "la valeur hex injectée doit rester binaire dans le message"
}
