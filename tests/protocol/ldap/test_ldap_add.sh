#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_add.sh — Tests AddRequest / AddResponse
#

ensh::import protocol/ldap/add

test::ldap_add_build_request() {
    declare -A attrs=()
    ldap::add::attrs_put attrs "objectClass" "top" "person"
    attrs["cn"]="alice"

    local msg
    ldap::add::build msg 1 "cn=alice,dc=test,dc=local" attrs

    local expected="304F020101684A0419636E3D616C6963652C64633D746573742C64633D6C6F63616C"
    expected+="302D300D0402636E31070405616C696365301C040B6F626A656374436C617373310D0403746F700406706572736F6E"

    assert::equal "${msg}" "${expected}" "AddRequest doit matcher le BER de référence"
}

test::ldap_add_build_request_array_values() {
    local -a classes=("top" "person")
    declare -A attrs=(
        [cn]="alice"
        [objectClass]="array:classes"
    )

    local msg
    ldap::add::build msg 1 "cn=alice,dc=test,dc=local" attrs

    local expected="304F020101684A0419636E3D616C6963652C64633D746573742C64633D6C6F63616C"
    expected+="302D300D0402636E31070405616C696365301C040B6F626A656374436C617373310D0403746F700406706572736F6E"

    assert::equal "${msg}" "${expected}" "AddRequest via array:nom_tableau doit rester identique"
}

test::ldap_add_build_request_hex_value() {
    declare -A attrs=(
        [unicodePwd]="hex:220050004000730073002200"
    )

    local msg
    ldap::add::build msg 5 "cn=ws01,dc=test,dc=local" attrs

    local expected="303F020105683A0418636E3D777330312C64633D746573742C64633D6C6F63616C"
    expected+="301E301C040A756E69636F6465507764310E040C220050004000730073002200"

    assert::equal "${msg}" "${expected}" "AddRequest doit conserver les valeurs binaires injectées"
}

test::ldap_add_parse_response_success() {
    local resp="300C02010169070A010004000400"
    declare -A parsed=()
    ldap::add::parse_response "${resp}" parsed

    assert::equal "${parsed[msg_id]}" "1" "message id lu"
    assert::equal "${parsed[op_tag]}" "69" "AddResponse attendu"
    assert::equal "${parsed[result_code]}" "0" "result code success"
    assert::equal "${parsed[result_name]}" "success" "nom du result code"
}

test::ldap_add_parse_response_error() {
    local resp="302B02010569260A0135041064633D746573742C64633D6C6F63616C04116F626A6563742065786973747320"
    declare -A parsed=()
    ldap::add::parse_response "${resp}" parsed

    assert::equal "${parsed[result_code]}" "53" "result code lu"
    assert::equal "${parsed[result_name]}" "unwillingToPerform" "nom lisible du result code"
    assert::equal "${parsed[matched_dn]}" "dc=test,dc=local" "matchedDN lu"
}
