#!/usr/bin/env bash
#
# lib/protocol/ldap/add.sh — AddRequest / AddResponse LDAP
#
# Implémente l'ajout d'objets LDAP (RFC 4511 §4.7).
#

[[ -n "${_ENSH_PROTO_LDAP_ADD:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_ADD=1

ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1
ensh::import protocol/ldap/message

# ldap::add::attrs_put <attrs_dict_var> <attr> [value...]
#
# Helper de confort pour stocker plusieurs valeurs dans un tableau associatif.
# Les valeurs sont jointes par des retours à la ligne, puis ré-expansées par build().
ldap::add::attrs_put() {
    local -n _ldap_ap_dict="$1"
    local attr="$2"
    shift 2

    local joined=""
    local sep=""
    local value
    for value in "$@"; do
        joined+="${sep}${value}"
        sep=$'\n'
    done
    _ldap_ap_dict["${attr}"]="${joined}"
}

# ldap::add::_value_to_hex <value> <var_out>
#
# Accepte soit une chaîne brute, soit une valeur préfixée par 'hex:'.
ldap::add::_value_to_hex() {
    local value="$1"
    local -n _ldap_avh_out="$2"

    if [[ "${value}" == hex:* || "${value}" == HEX:* ]]; then
        _ldap_avh_out="${value#*:}"
        _ldap_avh_out="${_ldap_avh_out^^}"
        if ! hex::is_valid "${_ldap_avh_out}"; then
            log::error "ldap::add : valeur hex invalide '${value}'"
            return 1
        fi
    else
        hex::from_string "${value}" _ldap_avh_out
    fi
}

# ldap::add::_expand_attr_values <spec> <var_array_out>
#
# Formats supportés :
#   - "valeur"                  → une valeur
#   - $'v1\nv2'                 → plusieurs valeurs
#   - "array:nom_du_tableau"    → tableau indexé existant
# Les éléments du tableau peuvent eux-mêmes utiliser le préfixe 'hex:'.
ldap::add::_expand_attr_values() {
    local spec="$1"
    local -n _ldap_aev_out="$2"
    _ldap_aev_out=()

    if [[ "${spec}" == array:* || "${spec}" == ARRAY:* ]]; then
        local arr_name="${spec#*:}"
        local arr_decl
        arr_decl="$(declare -p "${arr_name}" 2>/dev/null)" || {
            log::error "ldap::add : tableau '${arr_name}' introuvable"
            return 1
        }
        [[ "${arr_decl}" == "declare -a"* ]] || {
            log::error "ldap::add : '${arr_name}' n'est pas un tableau indexé"
            return 1
        }
        local -n arr_ref="${arr_name}"
        _ldap_aev_out=("${arr_ref[@]}")
        return 0
    fi

    if [[ "${spec}" == *$'\n'* ]]; then
        local line
        while IFS= read -r line || [[ -n "${line}" ]]; do
            _ldap_aev_out+=("${line}")
        done <<< "${spec}"
    else
        _ldap_aev_out=("${spec}")
    fi
}

# ldap::add::build <var_out> <msg_id> <dn> <attrs_dict_var>
#
# Construit un LDAPMessage complet contenant un AddRequest.
# <attrs_dict_var> doit référencer un tableau associatif :
#   attr -> valeur simple, valeurs séparées par '\n', ou "array:nom_tableau".
ldap::add::build() {
    local -n _ldap_ab_out="$1"
    local -i msg_id="$2"
    local dn="$3"
    local -n _ldap_ab_attrs="$4"

    local dn_hex
    hex::from_string "${dn}" dn_hex
    local dn_os
    asn1::octet_string "${dn_hex}" dn_os

    local -a attr_names=()
    mapfile -t attr_names < <(printf '%s\n' "${!_ldap_ab_attrs[@]}" | sort)

    local attrs_content=""
    local attr attr_hex attr_os
    for attr in "${attr_names[@]}"; do
        hex::from_string "${attr}" attr_hex
        asn1::octet_string "${attr_hex}" attr_os

        local spec="${_ldap_ab_attrs[${attr}]}"
        local -a values=()
        ldap::add::_expand_attr_values "${spec}" values || return 1

        local vals_content=""
        local value value_hex value_os
        for value in "${values[@]}"; do
            ldap::add::_value_to_hex "${value}" value_hex || return 1
            asn1::octet_string "${value_hex}" value_os
            vals_content+="${value_os}"
        done

        local vals_set partial_attr
        asn1::set "${vals_content}" vals_set
        asn1::sequence "${attr_os}${vals_set}" partial_attr
        attrs_content+="${partial_attr}"
    done

    local attrs_seq add_req
    asn1::sequence "${attrs_content}" attrs_seq
    asn1::tlv "68" "${dn_os}${attrs_seq}" add_req

    ldap::message::wrap "${msg_id}" "${add_req}" _ldap_ab_out
}

# ldap::add::parse_response <hex_data> <var_dict_out>
#
# Accepte soit un LDAPMessage complet, soit la valeur interne d'un AddResponse.
ldap::add::parse_response() {
    local hex_data="${1^^}"
    local -n _ldap_apr_dict="$2"

    local op_value="${hex_data}"

    if [[ "${hex_data:0:2}" == "30" ]]; then
        declare -A _ldap_apr_msg=()
        ldap::message::parse "${hex_data}" _ldap_apr_msg || return 1
        _ldap_apr_dict[msg_id]="${_ldap_apr_msg[msg_id]}"
        _ldap_apr_dict[op_tag]="${_ldap_apr_msg[op_tag]}"

        if [[ "${_ldap_apr_msg[op_tag]}" != "69" ]]; then
            log::error "ldap::add::parse_response : AddResponse attendu, tag=0x${_ldap_apr_msg[op_tag]}"
            return 1
        fi

        op_value="${_ldap_apr_msg[op_value]}"
    fi

    ldap::message::parse_ldapresult "${op_value}" _ldap_apr_dict || return 1
}

# ldap::add::is_success <var_dict_out>
ldap::add::is_success() {
    local -n _ldap_ais_dict="$1"
    [[ "${_ldap_ais_dict[result_code]}" == "0" ]]
}
