#!/usr/bin/env bash
#
# tests/encoding/test_asn1.sh — Tests unitaires pour lib/encoding/asn1.sh
#

ensh::import encoding/asn1

test::asn1_encode_length() {
    local out

    asn1::encode_length 0 out
    assert::equal "${out}" "00" "longueur 0 → forme courte"

    asn1::encode_length 127 out
    assert::equal "${out}" "7F" "longueur 127 → forme courte max"

    asn1::encode_length 128 out
    assert::equal "${out}" "8180" "longueur 128 → forme longue 1 octet"

    asn1::encode_length 255 out
    assert::equal "${out}" "81FF" "longueur 255 → forme longue 1 octet"

    asn1::encode_length 256 out
    assert::equal "${out}" "820100" "longueur 256 → forme longue 2 octets"

    asn1::encode_length 65535 out
    assert::equal "${out}" "82FFFF" "longueur 65535 → forme longue 2 octets"
}

test::asn1_decode_length() {
    local len hdr

    asn1::decode_length "7F" 0 len hdr
    assert::equal "${len}" "127" "décode forme courte 0x7F"
    assert::equal "${hdr}" "1"   "header size = 1"

    asn1::decode_length "8180" 0 len hdr
    assert::equal "${len}" "128" "décode forme longue 0x8180"
    assert::equal "${hdr}" "2"   "header size = 2"

    asn1::decode_length "820100" 0 len hdr
    assert::equal "${len}" "256" "décode forme longue 0x820100"
    assert::equal "${hdr}" "3"   "header size = 3"
}

test::asn1_tlv() {
    local out

    asn1::tlv "04" "4142" out
    assert::equal "${out}" "04024142" "OCTET STRING 'AB'"

    asn1::tlv "30" "" out
    assert::equal "${out}" "3000" "SEQUENCE vide"

    asn1::tlv "02" "01" out
    assert::equal "${out}" "020101" "INTEGER 1"
}

test::asn1_integer() {
    local out

    asn1::integer "01" out
    assert::equal "${out}" "020101" "integer 0x01"

    asn1::integer "7F" out
    assert::equal "${out}" "02017F" "integer 0x7F (pas de byte de signe)"

    asn1::integer "FF" out
    assert::equal "${out}" "020200FF" "integer 0xFF (ajout byte de signe 0x00)"

    asn1::integer "80" out
    assert::equal "${out}" "02020080" "integer 0x80 (ajout byte de signe 0x00)"

    asn1::integer "" out
    assert::equal "${out}" "020100" "integer vide → 0x00"
}

test::asn1_sequence_set() {
    local out

    asn1::sequence "020101" out
    assert::equal "${out}" "3003020101" "SEQUENCE avec INTEGER 1"

    asn1::set "020101" out
    assert::equal "${out}" "3103020101" "SET avec INTEGER 1"
}

test::asn1_string_types() {
    local out

    asn1::octet_string "4142" out
    assert::equal "${out}" "04024142" "OCTET STRING"

    asn1::general_string "AB" out
    assert::equal "${out}" "1B024142" "GeneralString 'AB'"

    asn1::ia5_string "hi" out
    assert::equal "${out}" "16026869" "IA5String 'hi'"

    asn1::utf8_string "ok" out
    assert::equal "${out}" "0C026F6B" "UTF8String 'ok'"
}

test::asn1_null() {
    local out
    asn1::null out
    assert::equal "${out}" "0500" "NULL"
}

test::asn1_context_tag() {
    local out

    asn1::context_tag 0 "020101" out
    assert::equal "${out}" "A003020101" "[0] EXPLICIT INTEGER 1"

    asn1::context_tag 3 "4142" out
    assert::equal "${out}" "A3024142" "[3] avec données"
}

test::asn1_oid() {
    local out

    # OID SPNEGO : 1.3.6.1.5.5.2 → 06 06 2B 06 01 05 05 02
    asn1::oid "1.3.6.1.5.5.2" out
    assert::equal "${out}" "${ASN1_OID_SPNEGO}" "OID SPNEGO 1.3.6.1.5.5.2"
}

test::asn1_parse_tlv_roundtrip() {
    local tag len val next

    # Parser un INTEGER simple
    asn1::parse_tlv "020101" 0 tag len val next
    assert::equal "${tag}" "02" "parse_tlv : tag INTEGER"
    assert::equal "${len}" "1"  "parse_tlv : longueur 1"
    assert::equal "${val}" "01" "parse_tlv : valeur 0x01"
    assert::equal "${next}" "3" "parse_tlv : offset suivant"

    # Parser une SEQUENCE avec contenu
    asn1::parse_tlv "3003020101" 0 tag len val next
    assert::equal "${tag}" "30"     "parse_tlv SEQUENCE : tag"
    assert::equal "${len}" "3"      "parse_tlv SEQUENCE : longueur"
    assert::equal "${val}" "020101" "parse_tlv SEQUENCE : valeur"
    assert::equal "${next}" "5"     "parse_tlv SEQUENCE : offset suivant"
}

test::asn1_bit_string() {
    local out
    asn1::bit_string "AABB" out
    # BIT STRING tag=03, len=3 (00 + 2 octets data), 00 (unused bits) + AABB
    assert::equal "${out}" "030300AABB" "BIT STRING"
}
