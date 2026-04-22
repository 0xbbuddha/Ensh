#!/usr/bin/env bash
#
# tests/protocol/llmnr/test_llmnr_message.sh — Tests LLMNR wire format
#

ensh::import protocol/llmnr/message

test::llmnr_message_build_query_a() {
    local msg
    llmnr::message::build_query msg "BEEF" "fileserver"

    local expected="BEEF000000010000000000000A66696C657365727665720000010001"
    assert::equal "${msg}" "${expected}" "requête LLMNR A"
}

test::llmnr_message_build_query_aaaa() {
    local msg
    llmnr::message::build_query msg "1234" "ws01.pirate.htb" "AAAA"

    local expected="1234000000010000000000000477733031067069726174650368746200001C0001"
    assert::equal "${msg}" "${expected}" "requête LLMNR AAAA"
}

test::llmnr_message_build_response_a() {
    local msg
    llmnr::message::build_response msg "BEEF" "fileserver" "C0A8010A"

    local expected="BEEF800000010001000000000A66696C657365727665720000010001"
    expected+="C00C000100010000001E0004C0A8010A"
    assert::equal "${msg}" "${expected}" "réponse LLMNR IPv4"
}

test::llmnr_message_parse_response() {
    local msg="BEEF800000010001000000000A66696C657365727665720000010001"
    msg+="C00C000100010000001E0004C0A8010A"

    declare -A parsed=()
    llmnr::message::parse "${msg}" parsed

    assert::equal "${parsed[txid]}" "BEEF" "txid lu"
    assert::equal "${parsed[qr]}" "1" "message de réponse"
    assert::equal "${parsed[question_name]}" "fileserver" "nom demandé"
    assert::equal "${parsed[qtype_name]}" "A" "type demandé"
    assert::equal "${parsed[answer_count]}" "1" "une réponse"
    assert::equal "${parsed[answer_0_name]}" "fileserver" "nom de la réponse"
    assert::equal "${parsed[answer_0_type_name]}" "A" "type de la réponse"
    assert::equal "${parsed[answer_0_ip]}" "192.168.1.10" "IP parsée"
}
