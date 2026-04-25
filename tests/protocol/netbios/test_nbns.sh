#!/usr/bin/env bash
#
# tests/protocol/netbios/test_nbns.sh — Tests NBNS wire format
#

ensh::import protocol/netbios/nbns

test::nbns_build_query_nb() {
    local msg
    nbns::query::build msg "BEEF" "FILESERVER" "20"

    local expected="BEEF29000001000000000000204547454A454D45464644454646434647454646434341434143414341434143410000200001"
    assert::equal "${msg}" "${expected}" "requête NBNS Name Query"
}

test::nbns_build_query_node_status() {
    local msg
    nbns::query::build_node_status msg "1234" "*"

    local expected="12340000000100000000000020434B4141414141414141414141414141414141414141414141414141414141410000210001"
    assert::equal "${msg}" "${expected}" "requête NBSTAT wildcard"
}

test::nbns_build_positive_response() {
    local msg
    nbns::response::build msg "BEEF" "FILESERVER" "C0A8010A" 300 "20"

    local expected="BEEF84000000000100000000204547454A454D454646444546464346474546464343414341434143414341434100002000010000012C00060000C0A8010A"
    assert::equal "${msg}" "${expected}" "réponse NBNS positive"
}

test::nbns_parse_positive_response() {
    local msg="BEEF84000000000100000000204547454A454D454646444546464346474546464343414341434143414341434100002000010000012C00060000C0A8010A"

    declare -A parsed=()
    nbns::parse "${msg}" parsed

    assert::equal "${parsed[txid]}" "BEEF" "txid lu"
    assert::equal "${parsed[qr]}" "1" "message de réponse"
    assert::equal "${parsed[answer_count]}" "1" "une réponse"
    assert::equal "${parsed[answer_0_name]}" "FILESERVER" "nom de la réponse"
    assert::equal "${parsed[answer_0_suffix]}" "20" "suffixe de la réponse"
    assert::equal "${parsed[answer_0_type_name]}" "NB" "type NB"
    assert::equal "${parsed[answer_0_nb_flags]}" "0000" "flags NB"
    assert::equal "${parsed[answer_0_ip]}" "192.168.1.10" "IP parsée"
}

test::nbns_parse_node_status_response() {
    local qname="20434B41414141414141414141414141414141414141414141414141414141414100"
    local name_hex stats_hex rdlength_hex msg

    hex::from_string "FILESERVER     " name_hex
    stats_hex="AABBCCDDEEFF0000000000000000000000000000000000000000000000000000000000000000000000000000"
    endian::be16 65 rdlength_hex

    msg="123484000000000100000000${qname}0021000100000000${rdlength_hex}"
    msg+="01${name_hex}200400${stats_hex}"

    declare -A parsed=()
    nbns::parse "${msg}" parsed

    assert::equal "${parsed[answer_0_type_name]}" "NBSTAT" "type NBSTAT"
    assert::equal "${parsed[answer_0_node_count]}" "1" "une entrée node status"
    assert::equal "${parsed[answer_0_node_0_name]}" "FILESERVER" "nom NBSTAT"
    assert::equal "${parsed[answer_0_node_0_suffix]}" "20" "suffixe NBSTAT"
    assert::equal "${parsed[answer_0_node_0_flags]}" "0400" "flags NBSTAT"
    assert::equal "${parsed[answer_0_mac]}" "AA:BB:CC:DD:EE:FF" "MAC NBSTAT"
}
