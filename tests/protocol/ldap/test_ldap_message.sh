#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_message.sh — Tests LDAPMessage
#

ensh::import protocol/ldap/message

test::ldap_message_wrap_simple() {
    # Construire un faux protocolOp (0x60 = BindRequest tag, contenu vide)
    local fake_op
    asn1::tlv "60" "" fake_op

    local msg
    ldap::message::wrap 1 "${fake_op}" msg

    # Doit commencer par SEQUENCE (0x30)
    assert::equal "${msg:0:2}" "30" "LDAPMessage commence par SEQUENCE"
    assert::not_empty "${msg}" "LDAPMessage non vide"
}

test::ldap_message_wrap_parse_roundtrip() {
    ldap::message::reset_id

    local fake_op
    asn1::tlv "64" "4142" fake_op    # SearchResultEntry avec 2 octets de data

    local mid; ldap::message::next_id mid
    local msg
    ldap::message::wrap "${mid}" "${fake_op}" msg

    declare -A parsed=()
    ldap::message::parse "${msg}" parsed

    assert::equal "${parsed[msg_id]}" "1" "MessageID roundtrip"
    assert::equal "${parsed[op_tag]}" "64" "op_tag SearchResultEntry"
    assert::equal "${parsed[op_value]}" "4142" "op_value roundtrip"
}

test::ldap_message_id_autoincrement() {
    ldap::message::reset_id

    local id1 id2 id3
    ldap::message::next_id id1
    ldap::message::next_id id2
    ldap::message::next_id id3

    assert::equal "${id1}" "1" "premier ID = 1"
    assert::equal "${id2}" "2" "deuxième ID = 2"
    assert::equal "${id3}" "3" "troisième ID = 3"
}

test::ldap_message_rc_name() {
    assert::equal "$(ldap::message::rc_name 0)" "success" "rc 0 = success"
    assert::equal "$(ldap::message::rc_name 49)" "invalidCredentials" "rc 49 = invalidCredentials"
    assert::equal "$(ldap::message::rc_name 999)" "unknown(999)" "rc inconnu"
}
