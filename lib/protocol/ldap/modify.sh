#!/usr/bin/env bash
#
# lib/protocol/ldap/modify.sh — ModifyRequest / ModifyResponse LDAP
#
# Implémente la modification d'attributs LDAP (RFC 4511 §4.6).
#

[[ -n "${_ENSH_PROTO_LDAP_MODIFY:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_MODIFY=1

ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1
ensh::import encoding/utf16
ensh::import protocol/ldap/message

readonly LDAP_MOD_ADD=0
readonly LDAP_MOD_DELETE=1
readonly LDAP_MOD_REPLACE=2

# ldap::modify::_op_to_int <op> <var_out>
#
# Accepte un entier (0/1/2) ou un alias lisible (add/delete/replace).
ldap::modify::_op_to_int() {
    local op="$1"
    local -n _ldap_moi_out="$2"

    case "${op}" in
        0|add|ADD) _ldap_moi_out="${LDAP_MOD_ADD}" ;;
        1|del|delete|DELETE) _ldap_moi_out="${LDAP_MOD_DELETE}" ;;
        2|replace|REPLACE) _ldap_moi_out="${LDAP_MOD_REPLACE}" ;;
        *)
            log::error "ldap::modify : opération invalide '${op}'"
            return 1
            ;;
    esac
}

# ldap::modify::_value_to_hex <value> <var_out>
#
# Par défaut, les valeurs sont encodées comme des chaînes ASCII/UTF-8 brutes.
# Préfixer par 'hex:' pour injecter directement des octets déjà encodés.
ldap::modify::_value_to_hex() {
    local value="$1"
    local -n _ldap_mvh_out="$2"

    if [[ "${value}" == hex:* || "${value}" == HEX:* ]]; then
        _ldap_mvh_out="${value#*:}"
        _ldap_mvh_out="${_ldap_mvh_out^^}"
        if ! hex::is_valid "${_ldap_mvh_out}"; then
            log::error "ldap::modify : valeur hex invalide '${value}'"
            return 1
        fi
    else
        hex::from_string "${value}" _ldap_mvh_out
    fi
}

# ldap::modify::encode_unicode_pwd <password> <var_out>
#
# Encode un mot de passe AD pour unicodePwd :
#   chaîne entre guillemets + UTF-16LE
ldap::modify::encode_unicode_pwd() {
    local password="$1"
    local -n _ldap_mup_out="$2"
    local quoted="\"${password}\""
    utf16::encode_le "${quoted}" _ldap_mup_out
}

# ldap::modify::build <var_out> <msg_id> <dn> <op> <attr> [value...]
#
# Construit un LDAPMessage complet contenant un ModifyRequest.
# Les valeurs peuvent être passées en clair ou préfixées par 'hex:'.
ldap::modify::build() {
    local -n _ldap_mb_out="$1"
    local -i msg_id="$2"
    local dn="$3"
    local op="$4"
    local attr="$5"
    shift 5
    local -a values=("$@")

    local -i op_int
    ldap::modify::_op_to_int "${op}" op_int || return 1

    local dn_hex attr_hex
    hex::from_string "${dn}" dn_hex
    hex::from_string "${attr}" attr_hex

    local dn_os attr_os
    asn1::octet_string "${dn_hex}" dn_os
    asn1::octet_string "${attr_hex}" attr_os

    local op_hex op_tlv
    printf -v op_hex '%02X' "${op_int}"
    asn1::tlv "0A" "${op_hex}" op_tlv

    local vals_content=""
    local value value_hex value_os
    for value in "${values[@]}"; do
        ldap::modify::_value_to_hex "${value}" value_hex || return 1
        asn1::octet_string "${value_hex}" value_os
        vals_content+="${value_os}"
    done

    local vals_set partial_attr change_seq changes_seq modify_req
    asn1::set "${vals_content}" vals_set
    asn1::sequence "${attr_os}${vals_set}" partial_attr
    asn1::sequence "${op_tlv}${partial_attr}" change_seq
    asn1::sequence "${change_seq}" changes_seq
    asn1::tlv "66" "${dn_os}${changes_seq}" modify_req

    ldap::message::wrap "${msg_id}" "${modify_req}" _ldap_mb_out
}

# ldap::modify::parse_response <hex_data> <var_dict_out>
#
# Accepte soit un LDAPMessage complet, soit la valeur interne d'un ModifyResponse.
ldap::modify::parse_response() {
    local hex_data="${1^^}"
    local -n _ldap_mpr_dict="$2"

    local op_value="${hex_data}"

    if [[ "${hex_data:0:2}" == "30" ]]; then
        declare -A _ldap_mpr_msg=()
        ldap::message::parse "${hex_data}" _ldap_mpr_msg || return 1
        _ldap_mpr_dict[msg_id]="${_ldap_mpr_msg[msg_id]}"
        _ldap_mpr_dict[op_tag]="${_ldap_mpr_msg[op_tag]}"

        if [[ "${_ldap_mpr_msg[op_tag]}" != "67" ]]; then
            log::error "ldap::modify::parse_response : ModifyResponse attendu, tag=0x${_ldap_mpr_msg[op_tag]}"
            return 1
        fi

        op_value="${_ldap_mpr_msg[op_value]}"
    fi

    ldap::message::parse_ldapresult "${op_value}" _ldap_mpr_dict || return 1
}

# ldap::modify::is_success <var_dict_out>
ldap::modify::is_success() {
    local -n _ldap_mis_dict="$1"
    [[ "${_ldap_mis_dict[result_code]}" == "0" ]]
}
