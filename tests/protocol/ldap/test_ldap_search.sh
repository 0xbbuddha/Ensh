#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_search.sh — Tests pour ldap/search.sh
#

ensh::import protocol/ldap/search
ensh::import protocol/ldap/filter
ensh::import protocol/ldap/message

# ── SearchRequest ─────────────────────────────────────────────────────────────

test::ldap_search_build_tag() {
    local filt out
    ldap::filter::present "objectClass" filt

    ldap::search::build "dc=test,dc=com" "${LDAP_SCOPE_SUB}" "${filt}" out
    # Doit commencer par [APPLICATION 3] = 0x63
    assert::equal "${out:0:2}" "63" "SearchRequest commence par tag 63"
    assert::not_empty "${out}" "SearchRequest non vide"
}

test::ldap_search_scope_constants() {
    assert::equal "${LDAP_SCOPE_BASE}" "0" "LDAP_SCOPE_BASE = 0"
    assert::equal "${LDAP_SCOPE_ONE}"  "1" "LDAP_SCOPE_ONE = 1"
    assert::equal "${LDAP_SCOPE_SUB}"  "2" "LDAP_SCOPE_SUB = 2"
}

test::ldap_search_with_attributes() {
    local filt req
    ldap::filter::present "objectClass" filt
    ldap::search::build "dc=corp,dc=local" 2 "${filt}" req 0 0 0 \
        "sAMAccountName" "mail"

    assert::equal "${req:0:2}" "63" "SearchRequest avec attributs commence par 63"
    # La taille doit être supérieure à sans attributs
    local filt2 req_no_attrs
    ldap::search::build "dc=corp,dc=local" 2 "${filt2:-${filt}}" req_no_attrs
    assert::not_equal "${#req}" "${#req_no_attrs}" "avec attrs > sans attrs"
}

test::ldap_search_base_dn_encoded() {
    local filt req
    ldap::filter::present "objectClass" filt
    ldap::search::build "dc=test,dc=com" 0 "${filt}" req

    # "dc=test,dc=com" en hex doit être présent dans le message
    local dn_hex
    hex::from_string "dc=test,dc=com" dn_hex

    # Vérifier que le DN encodé est dans le SearchRequest
    local contains=0
    [[ "${req}" == *"${dn_hex}"* ]] && contains=1
    assert::equal "${contains}" "1" "base DN présent dans SearchRequest"
}

# ── parse_entry ───────────────────────────────────────────────────────────────

_build_test_entry() {
    local -n _bte_out="$1"
    local dn_str="cn=Alice,dc=test,dc=com"
    local attr_name="sAMAccountName"
    local attr_val="alice"

    # objectName (DN) en OCTET STRING
    local dn_hex os_dn
    hex::from_string "${dn_str}" dn_hex
    asn1::octet_string "${dn_hex}" os_dn

    # PartialAttribute : SEQUENCE { type OCTET STRING, vals SET { OCTET STRING } }
    local name_hex os_name val_hex os_val set_vals pa_seq
    hex::from_string "${attr_name}" name_hex
    asn1::octet_string "${name_hex}" os_name

    hex::from_string "${attr_val}" val_hex
    asn1::octet_string "${val_hex}" os_val
    asn1::tlv "31" "${os_val}" set_vals    # SET

    asn1::sequence "${os_name}${set_vals}" pa_seq

    # Deuxième attribut : cn = Alice
    local cn_name_hex os_cn_name cn_val_hex os_cn_val set_cn pa_cn
    hex::from_string "cn" cn_name_hex
    asn1::octet_string "${cn_name_hex}" os_cn_name
    hex::from_string "Alice" cn_val_hex
    asn1::octet_string "${cn_val_hex}" os_cn_val
    asn1::tlv "31" "${os_cn_val}" set_cn
    asn1::sequence "${os_cn_name}${set_cn}" pa_cn

    # Liste des attributs
    local attrs_list
    asn1::sequence "${pa_seq}${pa_cn}" attrs_list

    _bte_out="${os_dn}${attrs_list}"
}

test::ldap_search_parse_entry_dn() {
    local entry_hex
    _build_test_entry entry_hex

    declare -A entry=()
    ldap::search::parse_entry "${entry_hex}" entry

    assert::equal "${entry[dn]}" "cn=Alice,dc=test,dc=com" "parse_entry : DN correct"
}

test::ldap_search_parse_entry_attrs() {
    local entry_hex
    _build_test_entry entry_hex

    declare -A entry=()
    ldap::search::parse_entry "${entry_hex}" entry

    assert::equal "${entry[attr:sAMAccountName]}" "alice" "parse_entry : sAMAccountName"
    assert::equal "${entry[attr:cn]}"             "Alice" "parse_entry : cn"
}

# ── Filter ────────────────────────────────────────────────────────────────────

test::ldap_filter_present() {
    local out
    ldap::filter::present "objectClass" out
    # [7] PRIMITIVE = 0x87, "objectClass" hex
    assert::equal "${out:0:2}" "87" "filter::present tag = 87"
    assert::not_empty "${out}" "filter présent non vide"
}

test::ldap_filter_equal() {
    local out
    ldap::filter::equal "objectClass" "user" out
    # [3] CONSTRUCTED = 0xA3
    assert::equal "${out:0:2}" "A3" "filter::equal tag = A3"
}

test::ldap_filter_and() {
    local f1 f2 fand
    ldap::filter::present "objectClass" f1
    ldap::filter::equal "sAMAccountName" "admin" f2
    ldap::filter::and fand "${f1}" "${f2}"
    # [0] = 0xA0
    assert::equal "${fand:0:2}" "A0" "filter::and tag = A0"
}

test::ldap_filter_or() {
    local f1 f2 for_out
    ldap::filter::present "objectClass" f1
    ldap::filter::present "cn" f2
    ldap::filter::or for_out "${f1}" "${f2}"
    # [1] = 0xA1
    assert::equal "${for_out:0:2}" "A1" "filter::or tag = A1"
}

test::ldap_filter_not() {
    local f1 fnot
    ldap::filter::present "objectClass" f1
    ldap::filter::not "${f1}" fnot
    # [2] = 0xA2
    assert::equal "${fnot:0:2}" "A2" "filter::not tag = A2"
}
