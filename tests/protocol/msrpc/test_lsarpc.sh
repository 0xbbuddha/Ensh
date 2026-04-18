#!/usr/bin/env bash
#
# tests/protocol/msrpc/test_lsarpc.sh -- Tests LSARPC / NDR
#

ensh::import protocol/msrpc/lsarpc

test::lsarpc_build_open_policy_stub() {
    local stub
    _lsarpc_build_open_policy_stub "${LSARPC_ACCESS_MAXIMUM_ALLOWED}" stub

    assert::equal "${stub}" \
        "0000000000000000000000000000000000000000000000000000000000000002" \
        "LsarOpenPolicy2 doit encoder SystemName=NULL + ObjectAttributes nuls + MAXIMUM_ALLOWED"
}

test::lsarpc_build_lookup_sids_stub_single_sid() {
    local handle stub
    local -a sids=("010100000000000512000000")
    handle="3333333333333333333333333333333333333333"

    _lsarpc_build_lookup_sids_stub "${handle}" sids stub

    assert::equal "${stub}" \
        "${handle}01000000000002000100000001000200010000000101000000000005120000000000000002000200000000000100000000000000" \
        "LsarLookupSids doit encoder SidEnumBuffer puis TranslatedNames vides"
}

test::lsarpc_sid_append_rid() {
    local sid out
    sid="01040000000000051500000001020304AABBCCDD11223344"

    lsarpc::sid::append_rid "${sid}" 500 out

    assert::equal "${out}" \
        "01050000000000051500000001020304AABBCCDD11223344F4010000" \
        "append_rid doit incrémenter le SubAuthorityCount puis ajouter le RID en LE32"
}

test::lsarpc_parse_query_info_policy_dns_resp() {
    local stub
    stub="000002000C000000"
    stub+="0C000C000100020014001400020002001400140003000200"
    stub+="78563412BC9AF0DE112233445566778804000200"
    stub+="060000000000000006000000500049005200410054004500"
    stub+="0A000000000000000A0000007000690072006100740065002E00680074006200"
    stub+="0A000000000000000A0000007000690072006100740065002E00680074006200"
    stub+="0400000001040000000000051500000001020304AABBCCDD11223344"
    stub+="00000000"

    local -A info=()
    _lsarpc_parse_query_info_policy_resp "${stub}" "${LSARPC_POLICY_INFO_DOMAIN_DNS}" info

    assert::equal "${info[class]}"       "12" "classe DomainDns correcte"
    assert::equal "${info[name]}"        "PIRATE" "nom NetBIOS décodé"
    assert::equal "${info[dns_domain]}"  "pirate.htb" "domaine DNS décodé"
    assert::equal "${info[dns_forest]}"  "pirate.htb" "forêt DNS décodée"
    assert::equal "${info[domain_guid]}" "12345678-9ABC-DEF0-1122-334455667788" "GUID décodé"
    assert::equal "${info[domain_sid]}"  "01040000000000051500000001020304AABBCCDD11223344" "SID domaine décodé"
}

test::lsarpc_parse_query_info_policy_audit_resp() {
    local stub
    stub="0000020002000000"
    stub+="010000000100020003000000"
    stub+="03000000010000000200000004000000"
    stub+="00000000"

    local -A info=()
    _lsarpc_parse_query_info_policy_resp "${stub}" "${LSARPC_POLICY_INFO_AUDIT_EVENTS}" info

    assert::equal "${info[class]}"                 "2" "classe AuditEvents correcte"
    assert::equal "${info[auditing_mode]}"         "1" "mode d'audit lu"
    assert::equal "${info[max_audit_event_count]}" "3" "MaximumAuditEventCount lu"
    assert::equal "${info[event_options_count]}"   "3" "trois options d'audit décodées"
    assert::equal "${info[event_options]}"         "1,2,4" "options d'audit alignées"
}

test::lsarpc_parse_enum_privileges_resp() {
    local stub
    stub="05000000020000000000020002000000"
    stub+="0A000A00010002001100000000000000"
    stub+="0A000A00020002002200000001000000"
    stub+="050000000000000005000000500072006900760041000000"
    stub+="050000000000000005000000500072006900760042000000"
    stub+="00000000"

    local -i next_ctx=0 status=0
    local -a privs=()
    _lsarpc_parse_enum_privileges_resp "${stub}" next_ctx privs status

    assert::equal "${next_ctx}"  "5" "EnumerationContext suivant lu"
    assert::equal "${status}"    "0" "status succès"
    assert::equal "${#privs[@]}" "2" "deux privilèges décodés"
    assert::equal "${privs[0]}"  "PrivA:0000000000000011" "premier privilège aligné"
    assert::equal "${privs[1]}"  "PrivB:0000000100000022" "second privilège avec HighPart non nul"
}

test::lsarpc_parse_lookup_sids_resp() {
    local stub
    stub="00000200"
    stub+="010000000100020001000000"
    stub+="010000000C000C000200020003000200"
    stub+="060000000000000006000000500049005200410054004500"
    stub+="0400000001040000000000051500000001020304AABBCCDD11223344"
    stub+="0100000004000200"
    stub+="01000000010000001A001A000500020000000000"
    stub+="0D000000000000000D000000410064006D0069006E006900730074007200610074006F0072000000"
    stub+="01000000"
    stub+="00000000"

    local -i mapped=0 status=0
    local -a names=()
    _lsarpc_parse_lookup_sids_resp "${stub}" names mapped status

    assert::equal "${status}"    "0" "status lookup_sids succès"
    assert::equal "${mapped}"    "1" "un SID mappé"
    assert::equal "${#names[@]}" "1" "une résolution retournée"
    assert::equal "${names[0]}"  "user:PIRATE:Administrator" "type, domaine et nom correctement alignés"
}
