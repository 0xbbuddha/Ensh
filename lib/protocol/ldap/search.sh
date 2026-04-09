#!/usr/bin/env bash
#
# lib/protocol/ldap/search.sh — SearchRequest et parsing des résultats
#
# La recherche LDAP est l'opération centrale pour interroger un annuaire AD.
#
# Structure SearchRequest (RFC 4511 §4.5.1) :
#   SearchRequest ::= [APPLICATION 3] SEQUENCE {
#       baseObject   LDAPDN,
#       scope        ENUMERATED { baseObject(0), singleLevel(1), wholeSubtree(2) },
#       derefAliases ENUMERATED { neverDerefAliases(0), derefInSearching(1),
#                                 derefFindingBaseObj(2), derefAlways(3) },
#       sizeLimit    INTEGER (0..maxInt),
#       timeLimit    INTEGER (0..maxInt),
#       typesOnly    BOOLEAN,
#       filter       Filter,
#       attributes   AttributeSelection
#   }
#
# Structure SearchResultEntry (RFC 4511 §4.5.2) :
#   SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
#       objectName LDAPDN,
#       attributes PartialAttributeList
#   }
#   PartialAttributeList ::= SEQUENCE OF PartialAttribute
#   PartialAttribute ::= SEQUENCE {
#       type   AttributeDescription,
#       vals   SET OF AttributeValue
#   }
#
# Référence : RFC 4511 §4.5
#
# Dépendances : core/hex, core/log, encoding/asn1, protocol/ldap/message
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LDAP_SEARCH:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_SEARCH=1

ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1
ensh::import protocol/ldap/message

# ── Constantes de scope (RFC 4511 §4.5.1) ────────────────────────────────────

readonly LDAP_SCOPE_BASE=0    # baseObject  — DN de base uniquement
readonly LDAP_SCOPE_ONE=1     # singleLevel — enfants directs du DN de base
readonly LDAP_SCOPE_SUB=2     # wholeSubtree — tout le sous-arbre (le plus courant)

# ── Constantes derefAliases ───────────────────────────────────────────────────

readonly LDAP_DEREF_NEVER=0
readonly LDAP_DEREF_SEARCHING=1
readonly LDAP_DEREF_FINDING=2
readonly LDAP_DEREF_ALWAYS=3

# ── Construction d'un SearchRequest ──────────────────────────────────────────

# ldap::search::build <base_dn> <scope_int> <filter_hex> <var_out>
#                     [size_limit] [time_limit] [types_only] [attr...]
#
# Construit une SearchRequest BER.
#
# <attr...> : liste d'attributs à retourner (vide = tous)
#             Exemples: "sAMAccountName" "mail" "memberOf"
#             "*" = tous les attributs utilisateur
#             "+" = tous les attributs opérationnels
#
# Exemple :
#   ldap::filter::ad_spn filt
#   ldap::search::build "dc=corp,dc=local" "${LDAP_SCOPE_SUB}" "${filt}" req \
#       0 30 0 "sAMAccountName" "servicePrincipalName"
ldap::search::build() {
    local base_dn="$1"
    local -i scope="$2"
    local filter="${3^^}"
    local -n _ldap_sb_out="$4"
    local -i size_limit="${5:-0}"
    local -i time_limit="${6:-0}"
    local -i types_only="${7:-0}"
    shift 7
    local -a attrs=("$@")

    # baseObject LDAPDN
    local base_hex
    hex::from_string "${base_dn}" base_hex
    local base_os
    asn1::octet_string "${base_hex}" base_os

    # scope ENUMERATED
    local scope_hex
    printf -v scope_hex '%02X' "${scope}"
    local scope_tlv
    asn1::tlv "0A" "${scope_hex}" scope_tlv

    # derefAliases ENUMERATED = neverDerefAliases
    local deref_tlv
    asn1::tlv "0A" "00" deref_tlv

    # sizeLimit INTEGER
    local sl_hex
    printf -v sl_hex '%02X' "${size_limit}"
    local sl_tlv
    asn1::integer "${sl_hex}" sl_tlv

    # timeLimit INTEGER
    local tl_hex
    printf -v tl_hex '%02X' "${time_limit}"
    local tl_tlv
    asn1::integer "${tl_hex}" tl_tlv

    # typesOnly BOOLEAN : FALSE=0x00, TRUE=0xFF
    local to_val="00"; (( types_only )) && to_val="FF"
    local to_tlv
    asn1::tlv "01" "${to_val}" to_tlv

    # attributes AttributeSelection ::= SEQUENCE OF LDAPString
    local attrs_content=""
    local attr
    for attr in "${attrs[@]}"; do
        local ah
        hex::from_string "${attr}" ah
        local a_os
        asn1::octet_string "${ah}" a_os
        attrs_content+="${a_os}"
    done
    local attrs_seq
    asn1::sequence "${attrs_content}" attrs_seq

    # SearchRequest [APPLICATION 3] = 0x63
    local content="${base_os}${scope_tlv}${deref_tlv}${sl_tlv}${tl_tlv}${to_tlv}${filter}${attrs_seq}"
    asn1::tlv "63" "${content}" _ldap_sb_out
}

# ── Parsing de SearchResultEntry ──────────────────────────────────────────────

# ldap::search::parse_entry <op_value_hex> <var_dict_name>
#
# Parse le contenu d'un SearchResultEntry.
# Le dictionnaire contiendra :
#   dn               — Distinguished Name de l'entrée
#   attr:<nom>       — Valeur(s) de l'attribut (séparées par '\n' si multiples)
#
# Exemple d'accès :
#   echo "${entry[dn]}"
#   echo "${entry[attr:sAMAccountName]}"
ldap::search::parse_entry() {
    local op_val="${1^^}"
    local -n _ldap_spe_dict="$2"

    # objectName LDAPDN (OCTET STRING)
    local dn_tag dn_len dn_val dn_next
    asn1::parse_tlv "${op_val}" 0 dn_tag dn_len dn_val dn_next
    hex::to_string "${dn_val}" _ldap_spe_dict[dn]

    # attributes SEQUENCE OF PartialAttribute
    local attrs_tag attrs_len attrs_val attrs_next
    asn1::parse_tlv "${op_val}" "${dn_next}" attrs_tag attrs_len attrs_val attrs_next

    # Itérer sur chaque PartialAttribute
    local -i off=0
    local -i attrs_byte_len=$(( ${#attrs_val} / 2 ))

    while (( off < attrs_byte_len )); do
        # PartialAttribute ::= SEQUENCE { type, vals SET }
        local pa_tag pa_len pa_val pa_next
        asn1::parse_tlv "${attrs_val}" "${off}" pa_tag pa_len pa_val pa_next

        # type AttributeDescription
        local type_tag type_len type_val type_next
        asn1::parse_tlv "${pa_val}" 0 type_tag type_len type_val type_next
        local attr_name
        hex::to_string "${type_val}" attr_name

        # vals SET OF AttributeValue
        local vals_tag vals_len vals_val vals_next
        asn1::parse_tlv "${pa_val}" "${type_next}" vals_tag vals_len vals_val vals_next

        # Itérer sur chaque valeur
        local -i voff=0
        local -i vals_byte_len=$(( ${#vals_val} / 2 ))
        local attr_key="attr:${attr_name}"
        _ldap_spe_dict["${attr_key}"]=""

        while (( voff < vals_byte_len )); do
            local v_tag v_len v_val v_next
            asn1::parse_tlv "${vals_val}" "${voff}" v_tag v_len v_val v_next
            local v_str
            hex::to_string "${v_val}" v_str

            if [[ -z "${_ldap_spe_dict[${attr_key}]}" ]]; then
                _ldap_spe_dict["${attr_key}"]="${v_str}"
            else
                _ldap_spe_dict["${attr_key}"]+=$'\n'"${v_str}"
            fi
            voff="${v_next}"
        done

        off="${pa_next}"
    done
}

# ldap::search::parse_entry_hex <op_value_hex> <var_dict_name>
#
# Variante de parse_entry qui conserve les valeurs en hexadécimal.
# Utile pour les attributs binaires (objectGUID, objectSid, nTSecurityDescriptor...).
ldap::search::parse_entry_hex() {
    local op_val="${1^^}"
    local -n _ldap_speh_dict="$2"

    local dn_tag dn_len dn_val dn_next
    asn1::parse_tlv "${op_val}" 0 dn_tag dn_len dn_val dn_next
    hex::to_string "${dn_val}" _ldap_speh_dict[dn]

    local attrs_tag attrs_len attrs_val attrs_next
    asn1::parse_tlv "${op_val}" "${dn_next}" attrs_tag attrs_len attrs_val attrs_next

    local -i off=0
    local -i attrs_byte_len=$(( ${#attrs_val} / 2 ))

    while (( off < attrs_byte_len )); do
        local pa_tag pa_len pa_val pa_next
        asn1::parse_tlv "${attrs_val}" "${off}" pa_tag pa_len pa_val pa_next

        local type_tag type_len type_val type_next
        asn1::parse_tlv "${pa_val}" 0 type_tag type_len type_val type_next
        local attr_name
        hex::to_string "${type_val}" attr_name

        local vals_tag vals_len vals_val vals_next
        asn1::parse_tlv "${pa_val}" "${type_next}" vals_tag vals_len vals_val vals_next

        local -i voff=0
        local -i vals_byte_len=$(( ${#vals_val} / 2 ))
        local attr_key="hex:${attr_name}"
        _ldap_speh_dict["${attr_key}"]=""

        while (( voff < vals_byte_len )); do
            local v_tag v_len v_val v_next
            asn1::parse_tlv "${vals_val}" "${voff}" v_tag v_len v_val v_next
            if [[ -z "${_ldap_speh_dict[${attr_key}]}" ]]; then
                _ldap_speh_dict["${attr_key}"]="${v_val}"
            else
                _ldap_speh_dict["${attr_key}"]+=$'\n'"${v_val}"
            fi
            voff="${v_next}"
        done

        off="${pa_next}"
    done
}

# ── Attributs courants Active Directory ───────────────────────────────────────

# Ensemble d'attributs pour une recherche d'utilisateurs AD standard
readonly -a LDAP_ATTRS_USER_BASIC=(
    "sAMAccountName"
    "displayName"
    "mail"
    "memberOf"
    "userAccountControl"
    "pwdLastSet"
    "lastLogon"
    "description"
)

readonly -a LDAP_ATTRS_SPN=(
    "sAMAccountName"
    "servicePrincipalName"
    "userAccountControl"
    "pwdLastSet"
)

readonly -a LDAP_ATTRS_COMPUTER=(
    "cn"
    "dNSHostName"
    "operatingSystem"
    "operatingSystemVersion"
    "lastLogon"
)
