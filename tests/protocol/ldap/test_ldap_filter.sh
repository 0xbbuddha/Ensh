#!/usr/bin/env bash
#
# tests/protocol/ldap/test_ldap_filter.sh — Tests des filtres LDAP
#

ensh::import protocol/ldap/filter

test::ldap_filter_equal_structure() {
    local filt
    ldap::filter::equal "cn" "admin" filt

    # Le filtre d'égalité doit commencer par le tag A3
    assert::equal "${filt:0:2}" "A3" "equalityMatch tag = A3"
    assert::not_empty "${filt}" "filtre non vide"
}

test::ldap_filter_present_structure() {
    local filt
    ldap::filter::present "objectClass" filt

    # Present = tag 87 (primitif contextuel [7])
    assert::equal "${filt:0:2}" "87" "present tag = 87"
}

test::ldap_filter_and_structure() {
    local f1 f2 fand
    ldap::filter::equal "objectClass" "user" f1
    ldap::filter::equal "cn" "admin" f2
    ldap::filter::and fand "${f1}" "${f2}"

    # AND = tag A0
    assert::equal "${fand:0:2}" "A0" "AND tag = A0"

    # Le contenu du AND doit contenir les deux filtres
    local fand_len=$(( ${#fand} / 2 ))
    local f1_len=$(( ${#f1} / 2 ))
    local f2_len=$(( ${#f2} / 2 ))
    [[ "${fand_len}" -gt "$(( f1_len + f2_len ))" ]]
    assert::not_empty "${fand}" "AND non vide"
}

test::ldap_filter_or_structure() {
    local f1 f2 filt
    ldap::filter::equal "sAMAccountName" "alice" f1
    ldap::filter::equal "sAMAccountName" "bob" f2
    ldap::filter::or filt "${f1}" "${f2}"

    assert::equal "${filt:0:2}" "A1" "OR tag = A1"
}

test::ldap_filter_not_structure() {
    local f1 fnot
    ldap::filter::present "userAccountControl" f1
    ldap::filter::not "${f1}" fnot

    assert::equal "${fnot:0:2}" "A2" "NOT tag = A2"
}

test::ldap_filter_ad_spn_not_empty() {
    local filt
    ldap::filter::ad_spn filt
    assert::not_empty "${filt}" "filtre ad_spn non vide"

    # Doit commencer par AND (A0)
    assert::equal "${filt:0:2}" "A0" "ad_spn commence par AND"
}

test::ldap_filter_substrings_initial() {
    local filt
    ldap::filter::substrings "cn" filt "John" "" ""

    # SubstringFilter tag = A4
    assert::equal "${filt:0:2}" "A4" "SubstringFilter tag = A4"
    assert::not_empty "${filt}" "filtre substrings non vide"
}

test::ldap_filter_equal_contains_attr_and_value() {
    local filt
    ldap::filter::equal "sAMAccountName" "Administrator" filt

    local attr_hex val_hex
    hex::from_string "sAMAccountName" attr_hex
    hex::from_string "Administrator" val_hex

    # L'encodage de l'attribut doit apparaître dans le filtre
    local filt_upper="${filt^^}" attr_upper="${attr_hex^^}" val_upper="${val_hex^^}"
    assert::not_empty "${filt_upper}" "filtre non vide"
    [[ "${filt_upper}" == *"${attr_upper}"* ]]
    assert::equal "$?" "0" "attribut présent dans le filtre BER"
    [[ "${filt_upper}" == *"${val_upper}"* ]]
    assert::equal "$?" "0" "valeur présente dans le filtre BER"
}
