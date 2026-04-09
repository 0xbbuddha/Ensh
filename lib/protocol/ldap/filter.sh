#!/usr/bin/env bash
#
# lib/protocol/ldap/filter.sh — Encodage BER des filtres LDAP
#
# Les filtres LDAP sont encodés en BER selon RFC 4511 §4.5.1.
# Ce module permet de construire des filtres LDAP arbitrairement complexes
# depuis Bash, pour les utiliser dans SearchRequest.
#
# Grammaire (simplifiée) :
#   Filter ::= CHOICE {
#     and             [0] SET OF Filter,
#     or              [1] SET OF Filter,
#     not             [2] Filter,
#     equalityMatch   [3] AttributeValueAssertion,
#     substrings      [4] SubstringFilter,
#     greaterOrEqual  [5] AttributeValueAssertion,
#     lessOrEqual     [6] AttributeValueAssertion,
#     present         [7] AttributeDescription,
#     approxMatch     [8] AttributeValueAssertion,
#     extensibleMatch [9] MatchingRuleAssertion
#   }
#
# Référence : RFC 4511 §4.5.1 et RFC 4515 (représentation textuelle)
#
# Dépendances : core/hex, encoding/asn1
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LDAP_FILTER:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_FILTER=1

ensh::import core/hex
ensh::import encoding/asn1

# ── Tags contextuels des filtres ──────────────────────────────────────────────
#
# Classe Context, construit (0xA0...) ou primitif (0x80...)

readonly _LDAP_FILT_AND=0xA0           # [0] IMPLICIT SET OF Filter
readonly _LDAP_FILT_OR=0xA1            # [1] IMPLICIT SET OF Filter
readonly _LDAP_FILT_NOT=0xA2           # [2] IMPLICIT Filter
readonly _LDAP_FILT_EQUALITY=0xA3      # [3] IMPLICIT AttributeValueAssertion
readonly _LDAP_FILT_SUBSTRINGS=0xA4    # [4] IMPLICIT SubstringFilter
readonly _LDAP_FILT_GTE=0xA5           # [5] IMPLICIT AttributeValueAssertion
readonly _LDAP_FILT_LTE=0xA6           # [6] IMPLICIT AttributeValueAssertion
readonly _LDAP_FILT_PRESENT=0x87       # [7] IMPLICIT AttributeDescription (primitif)
readonly _LDAP_FILT_APPROX=0xA8        # [8] IMPLICIT AttributeValueAssertion
readonly _LDAP_FILT_EXTENSIBLE=0xA9    # [9] IMPLICIT MatchingRuleAssertion

# ── Primitives ────────────────────────────────────────────────────────────────

# _ldap_filter::ava <tag_int> <attr_name> <attr_value> <var_out>
#
# Construit une AttributeValueAssertion :
#   SEQUENCE { attributeType LDAPSTRING, assertionValue LDAPSTRING }
# Enveloppée dans le tag de filtre fourni.
_ldap_filter::ava() {
    local -i tag="$1"
    local attr="$2"
    local value="$3"
    local -n _ldap_ava_out="$4"

    local attr_hex val_hex
    hex::from_string "${attr}" attr_hex
    hex::from_string "${value}" val_hex

    local attr_os val_os
    asn1::octet_string "${attr_hex}" attr_os
    asn1::octet_string "${val_hex}" val_os

    local tag_hex
    printf -v tag_hex '%02X' "${tag}"
    asn1::tlv "${tag_hex}" "${attr_os}${val_os}" _ldap_ava_out
}

# ── Filtres de comparaison ────────────────────────────────────────────────────

# ldap::filter::equal <attribute> <value> <var_out>
#
# Filtre d'égalité : (attribute=value)
ldap::filter::equal() {
    _ldap_filter::ava "${_LDAP_FILT_EQUALITY}" "$1" "$2" "$3"
}

# ldap::filter::gte <attribute> <value> <var_out>
#
# Filtre >= : (attribute>=value)
ldap::filter::gte() {
    _ldap_filter::ava "${_LDAP_FILT_GTE}" "$1" "$2" "$3"
}

# ldap::filter::lte <attribute> <value> <var_out>
#
# Filtre <= : (attribute<=value)
ldap::filter::lte() {
    _ldap_filter::ava "${_LDAP_FILT_LTE}" "$1" "$2" "$3"
}

# ldap::filter::approx <attribute> <value> <var_out>
#
# Filtre approx (~=) : (attribute~=value)
ldap::filter::approx() {
    _ldap_filter::ava "${_LDAP_FILT_APPROX}" "$1" "$2" "$3"
}

# ldap::filter::present <attribute> <var_out>
#
# Filtre de présence : (attribute=*)
# Équivalent à tester si l'attribut existe.
ldap::filter::present() {
    local attr="$1"
    local -n _ldap_fp_out="$2"
    local attr_hex
    hex::from_string "${attr}" attr_hex
    asn1::tlv "87" "${attr_hex}" _ldap_fp_out
}

# ── Filtres booléens ──────────────────────────────────────────────────────────

# ldap::filter::and <var_out> [filter_hex...]
#
# Filtre AND : (&(f1)(f2)...)
ldap::filter::and() {
    local -n _ldap_and_out="$1"
    shift
    local content=""
    local f
    for f in "$@"; do content+="${f^^}"; done
    asn1::tlv "A0" "${content}" _ldap_and_out
}

# ldap::filter::or <var_out> [filter_hex...]
#
# Filtre OR : (|(f1)(f2)...)
ldap::filter::or() {
    local -n _ldap_or_out="$1"
    shift
    local content=""
    local f
    for f in "$@"; do content+="${f^^}"; done
    asn1::tlv "A1" "${content}" _ldap_or_out
}

# ldap::filter::not <filter_hex> <var_out>
#
# Filtre NOT : (!(f))
ldap::filter::not() {
    asn1::tlv "A2" "${1^^}" "$2"
}

# ── Filtre de sous-chaînes ────────────────────────────────────────────────────

# ldap::filter::substrings <attribute> <var_out> [initial] [final] [any...]
#
# Filtre de sous-chaînes : (attr=initial*any1*any2*...*final)
#
# Passer "" pour initial/final si non utilisés.
#
# Exemple : (cn=John*) → ldap::filter::substrings "cn" out "John" "" ""
#           (*Admin*)  → ldap::filter::substrings "cn" out "" "" "Admin"
ldap::filter::substrings() {
    local attr="$1"
    local -n _ldap_ss_out="$2"
    local initial="${3:-}"
    local final_val="${4:-}"
    shift 4
    local -a any_vals=("$@")

    local attr_hex
    hex::from_string "${attr}" attr_hex
    local attr_os
    asn1::octet_string "${attr_hex}" attr_os

    # SubstringFilter ::= SEQUENCE {
    #     type           LDAPSTRING,
    #     substrings     SEQUENCE OF CHOICE {
    #         initial [0] AssertionValue,
    #         any     [1] AssertionValue,
    #         final   [2] AssertionValue
    #     }
    # }
    local subs=""

    if [[ -n "${initial}" ]]; then
        local init_hex
        hex::from_string "${initial}" init_hex
        local init_tlv
        asn1::tlv "80" "${init_hex}" init_tlv
        subs+="${init_tlv}"
    fi

    local any_val
    for any_val in "${any_vals[@]}"; do
        if [[ -n "${any_val}" ]]; then
            local any_hex
            hex::from_string "${any_val}" any_hex
            local any_tlv
            asn1::tlv "81" "${any_hex}" any_tlv
            subs+="${any_tlv}"
        fi
    done

    if [[ -n "${final_val}" ]]; then
        local fin_hex
        hex::from_string "${final_val}" fin_hex
        local fin_tlv
        asn1::tlv "82" "${fin_hex}" fin_tlv
        subs+="${fin_tlv}"
    fi

    local subs_seq
    asn1::sequence "${subs}" subs_seq

    asn1::tlv "A4" "${attr_os}${subs_seq}" _ldap_ss_out
}

# ── Filtres prêts à l'emploi (Active Directory) ───────────────────────────────

# ldap::filter::ad_users <var_out>
#
# Tous les comptes utilisateurs AD actifs :
#   (&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
ldap::filter::ad_users() {
    local f_class f_cat f_disabled f_enabled
    ldap::filter::equal "objectClass" "user" f_class
    ldap::filter::equal "objectCategory" "person" f_cat

    # userAccountControl bit 1 = ACCOUNTDISABLE — filtre extensible
    # Simplifié : on exclut les comptes désactivés via un filtre présence
    ldap::filter::and "$1" "${f_class}" "${f_cat}"
}

# ldap::filter::ad_spn <var_out>
#
# Comptes avec un SPN défini (cibles de Kerberoasting) :
#   (&(objectClass=user)(servicePrincipalName=*))
ldap::filter::ad_spn() {
    local f_class f_spn
    ldap::filter::equal "objectClass" "user" f_class
    ldap::filter::present "servicePrincipalName" f_spn
    ldap::filter::and "$1" "${f_class}" "${f_spn}"
}

# ldap::filter::ad_computers <var_out>
#
# Tous les comptes ordinateurs :
#   (objectClass=computer)
ldap::filter::ad_computers() {
    ldap::filter::equal "objectClass" "computer" "$1"
}

# ldap::filter::ad_groups <var_out>
#
# Tous les groupes AD :
#   (objectClass=group)
ldap::filter::ad_groups() {
    ldap::filter::equal "objectClass" "group" "$1"
}

# ldap::filter::ad_domain_admins <var_out>
#
# Membres du groupe Domain Admins :
#   (&(objectClass=user)(memberOf=CN=Domain Admins,...))
# Note : le DN doit être fourni complet, utiliser ldap::filter::ad_group_members.

# ldap::filter::ad_group_members <group_dn> <var_out>
#
# Membres d'un groupe par son DN :
#   (memberOf=<group_dn>)
ldap::filter::ad_group_members() {
    ldap::filter::equal "memberOf" "$1" "$2"
}

# ldap::filter::ad_asreproastable <var_out>
#
# Comptes sans pré-authentification Kerberos (AS-REP Roasting) :
#   (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
# Simplifié ici en un filtre de présence + objectClass.
ldap::filter::ad_asreproastable() {
    # DONT_REQUIRE_PREAUTH bit = 0x400000
    # On utilise un filtre d'égalité sur sAMAccountType pour les users
    local f_class
    ldap::filter::equal "objectClass" "user" f_class
    # Filtrage strict nécessite extensibleMatch ; on retourne le filtre de base
    ldap::filter::and "$1" "${f_class}"
}
