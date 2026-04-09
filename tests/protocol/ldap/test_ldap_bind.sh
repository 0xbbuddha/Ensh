#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_bind.sh — Tests du BindRequest LDAP
#

ensh::import protocol/ldap/bind
ensh::import protocol/ldap/message

test::ldap_bind_simple_tag() {
    local req
    ldap::bind::simple "cn=admin,dc=corp,dc=local" "password" req

    # BindRequest tag = 0x60
    assert::equal "${req:0:2}" "60" "BindRequest tag = 60"
}

test::ldap_bind_simple_in_message() {
    local req msg
    ldap::bind::simple "cn=user,dc=test,dc=local" "secret" req

    ldap::message::reset_id
    local mid; ldap::message::next_id mid
    ldap::message::wrap "${mid}" "${req}" msg

    # Message complet doit commencer par SEQUENCE
    assert::equal "${msg:0:2}" "30" "BindRequest dans LDAPMessage → SEQUENCE"

    # Parser le message retour
    declare -A parsed=()
    ldap::message::parse "${msg}" parsed

    assert::equal "${parsed[msg_id]}" "1" "MessageID = 1"
    assert::equal "${parsed[op_tag]}" "60" "op_tag = BindRequest"
}

test::ldap_bind_anonymous() {
    local req
    ldap::bind::anonymous req

    # Même structure que simple avec DN et password vides
    assert::equal "${req:0:2}" "60" "BindRequest anonyme tag = 60"
}

test::ldap_bind_sasl_mechanism() {
    local req
    ldap::bind::sasl "GSS-SPNEGO" req

    assert::equal "${req:0:2}" "60" "BindRequest SASL tag = 60"
    assert::not_empty "${req}" "BindRequest SASL non vide"

    # Le mécanisme "GSS-SPNEGO" doit apparaître dans le message
    local mech_hex
    hex::from_string "GSS-SPNEGO" mech_hex
    [[ "${req^^}" == *"${mech_hex^^}"* ]]
    assert::not_empty "${req}" "mécanisme GSS-SPNEGO présent"
}

test::ldap_bind_sasl_with_creds() {
    local req
    ldap::bind::sasl "NTLM" req "DEADBEEF"

    assert::equal "${req:0:2}" "60" "BindRequest SASL+creds tag = 60"

    local mech_hex
    hex::from_string "NTLM" mech_hex
    [[ "${req^^}" == *"${mech_hex^^}"* ]]
    assert::not_empty "${req}" "mécanisme NTLM + credentials"
}
