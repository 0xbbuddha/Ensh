#!/usr/bin/env bash
#
# lib/encoding/asn1.sh — Encodage/décodage ASN.1 DER (subset)
#
# Implémente les primitives ASN.1 DER nécessaires à SPNEGO et Kerberos :
#   - INTEGER, OCTET STRING, BIT STRING, OID
#   - SEQUENCE, SET
#   - Tags contextuels [N] EXPLICIT / IMPLICIT
#   - Encodage de longueur (forme courte et forme longue)
#
# Référence : X.690 (ISO/IEC 8825-1)
#
# Dépendances : core/hex, core/bytes
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_ENCODING_ASN1:-}" ]] && return 0
readonly _ENSH_ENCODING_ASN1=1

ensh::import core/hex
ensh::import core/bytes

# ── Tags universels ───────────────────────────────────────────────────────────

readonly ASN1_TAG_BOOLEAN=0x01
readonly ASN1_TAG_INTEGER=0x02
readonly ASN1_TAG_BIT_STRING=0x03
readonly ASN1_TAG_OCTET_STRING=0x04
readonly ASN1_TAG_NULL=0x05
readonly ASN1_TAG_OID=0x06
readonly ASN1_TAG_UTF8_STRING=0x0C
readonly ASN1_TAG_SEQUENCE=0x30
readonly ASN1_TAG_SET=0x31
readonly ASN1_TAG_GENERAL_STRING=0x1B
readonly ASN1_TAG_IA5_STRING=0x16
readonly ASN1_TAG_PRINTABLE_STRING=0x13

# ── Encodage de la longueur (X.690 §8.1.3) ───────────────────────────────────

# asn1::encode_length <length_int> <var_out>
#
# Encode une longueur en DER.
# < 128  → forme courte : 1 octet
# >= 128 → forme longue : 0x8N suivi de N octets (big-endian)
asn1::encode_length() {
    local -i len="$1"
    local -n _asn1_el_out="$2"

    if (( len < 128 )); then
        printf -v _asn1_el_out '%02X' "${len}"
    elif (( len < 256 )); then
        printf -v _asn1_el_out '81%02X' "${len}"
    elif (( len < 65536 )); then
        printf -v _asn1_el_out '82%04X' "${len}"
    else
        printf -v _asn1_el_out '83%06X' "${len}"
    fi
}

# asn1::decode_length <hex> <byte_offset> <var_len_out> <var_header_size_out>
#
# Décode une longueur DER à partir de <byte_offset>.
# <var_header_size_out> contient la taille en octets du champ longueur lui-même.
asn1::decode_length() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _asn1_dl_len="$3"
    local -n _asn1_dl_hdr="$4"

    local first=$(( 16#${hex:$(( off*2 )):2} ))

    if (( (first & 0x80) == 0 )); then
        # Forme courte
        _asn1_dl_len="${first}"
        _asn1_dl_hdr=1
    else
        local -i nb=$(( first & 0x7F ))
        _asn1_dl_hdr=$(( 1 + nb ))
        _asn1_dl_len=$(( 16#${hex:$(( (off+1)*2 )):$(( nb*2 ))} ))
    fi
}

# ── Primitives TLV ────────────────────────────────────────────────────────────

# asn1::tlv <tag_hex> <value_hex> <var_out>
#
# Construit un TLV (Tag-Length-Value) DER.
asn1::tlv() {
    local tag="${1^^}"
    local value="${2^^}"
    local -n _asn1_tlv_out="$3"
    local len_hex
    local -i vlen=$(( ${#value} / 2 ))
    asn1::encode_length "${vlen}" len_hex
    _asn1_tlv_out="${tag}${len_hex}${value}"
}

# ── Types de base ─────────────────────────────────────────────────────────────

# asn1::integer <hex_value> <var_out>
#
# Encode un INTEGER DER. Ajoute un octet 0x00 si le bit de poids fort est 1
# (pour distinguer des entiers négatifs — règle DER §8.3.3).
asn1::integer() {
    local val="${1^^}"
    local -n _asn1_int_out="$2"
    # Normaliser à une longueur paire (multiple de 2 nibbles)
    (( ${#val} % 2 != 0 )) && val="0${val}"
    # Ajouter 0x00 si le bit de poids fort est 1 (évite l'interprétation négative)
    if [[ -n "${val}" ]] && (( 16#${val:0:2} >= 0x80 )); then
        val="00${val}"
    fi
    [[ -z "${val}" ]] && val="00"
    asn1::tlv "02" "${val}" _asn1_int_out
}

# asn1::octet_string <hex_data> <var_out>
asn1::octet_string() {
    asn1::tlv "04" "$1" "$2"
}

# asn1::bit_string <hex_data> <var_out>
# Ajoute l'octet "nombre de bits inutilisés" (0x00 = tous utilisés).
asn1::bit_string() {
    local val="00${1^^}"
    asn1::tlv "03" "${val}" "$2"
}

# asn1::null <var_out>
asn1::null() {
    local -n _asn1_null_out="$1"
    _asn1_null_out="0500"
}

# asn1::sequence <hex_contents> <var_out>
asn1::sequence() {
    asn1::tlv "30" "$1" "$2"
}

# asn1::set <hex_contents> <var_out>
asn1::set() {
    asn1::tlv "31" "$1" "$2"
}

# asn1::context_tag <tag_number> <hex_contents> <var_out>
#
# Crée un tag contextuel [N] EXPLICIT (classe contextuelle, construit).
# Tag = 0xA0 | N
asn1::context_tag() {
    local -i n="$1"
    local -n _asn1_ct_out="$3"
    local tag
    printf -v tag '%02X' "$(( 0xA0 | n ))"
    asn1::tlv "${tag}" "${2^^}" _asn1_ct_out
}

# asn1::general_string <ascii_string> <var_out>
asn1::general_string() {
    local hex
    hex::from_string "$1" hex
    asn1::tlv "1B" "${hex}" "$2"
}

# asn1::ia5_string <ascii_string> <var_out>
asn1::ia5_string() {
    local hex
    hex::from_string "$1" hex
    asn1::tlv "16" "${hex}" "$2"
}

# asn1::utf8_string <ascii_string> <var_out>
asn1::utf8_string() {
    local hex
    hex::from_string "$1" hex
    asn1::tlv "0C" "${hex}" "$2"
}

# ── OID ───────────────────────────────────────────────────────────────────────

# asn1::oid <dotted_string> <var_out>
#
# Encode un OID depuis sa notation pointée (ex: "1.3.6.1.5.5.2").
# Encodage : premier sous-identifiant = 40*arc1 + arc2, puis Base-128 pour les suivants.
asn1::oid() {
    local dotted="$1"
    local -n _asn1_oid_out="$2"

    IFS='.' read -ra arcs <<< "${dotted}"
    local encoded=""
    local -i i

    for (( i=0; i<${#arcs[@]}; i++ )); do
        local -i arc="${arcs[${i}]}"

        if (( i == 0 )); then
            # Fusionner arc[0] et arc[1]
            local -i combined=$(( arc * 40 + arcs[1] ))
            printf -v encoded '%s%02X' "${encoded}" "${combined}"
            (( i++ ))
            continue
        fi

        # Encodage Base-128 (big-endian, bit 7 = continuation)
        if (( arc < 128 )); then
            printf -v encoded '%s%02X' "${encoded}" "${arc}"
        else
            local b128=""
            local -i v="${arc}"
            local first=1
            while (( v > 0 )); do
                local chunk=$(( v & 0x7F ))
                (( first )) || chunk=$(( chunk | 0x80 ))
                b128="$(printf '%02X' "${chunk}")${b128}"
                v=$(( v >> 7 ))
                first=0
            done
            encoded+="${b128}"
        fi
    done

    asn1::tlv "06" "${encoded}" _asn1_oid_out
}

# OIDs courants pré-calculés (SPNEGO, NTLMSSP)
readonly ASN1_OID_SPNEGO="06062B0601050502"      # 1.3.6.1.5.5.2
readonly ASN1_OID_NTLMSSP="06092A864882F71201020202"  # 1.3.6.1.4.1.311.2.2.10

# ── Décodage ─────────────────────────────────────────────────────────────────

# asn1::parse_tlv <hex> <byte_offset> <var_tag_out> <var_len_out> <var_value_out> <var_next_offset_out>
#
# Parse un TLV DER à partir de <byte_offset>.
# Remplit les variables de sortie.
asn1::parse_tlv() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _asn1_pt_tag="$3"
    local -n _asn1_pt_len="$4"
    local -n _asn1_pt_val="$5"
    local -n _asn1_pt_next="$6"

    # Tag (simplifié : on gère les tags 1 octet uniquement)
    _asn1_pt_tag="${hex:$(( off*2 )):2}"
    local -i hdr_size
    asn1::decode_length "${hex}" "$(( off + 1 ))" _asn1_pt_len hdr_size

    local -i value_off=$(( off + 1 + hdr_size ))
    _asn1_pt_val="${hex:$(( value_off*2 )):$(( _asn1_pt_len*2 ))}"
    _asn1_pt_next=$(( value_off + _asn1_pt_len ))
}
