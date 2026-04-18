#!/usr/bin/env bash
#
# lib/protocol/kerberos/asreq.sh — Kerberos AS-REQ / AS-REP / KRB-ERROR
#
# Sous-ensemble Kerberos v5 utile pour :
#   - construire un AS-REQ simple vers krbtgt/REALM
#   - parser un AS-REP pour récupérer l'enc-part exploitable en ASREPRoast
#   - parser un KRB-ERROR pour identifier un PREAUTH_REQUIRED, etc.
#

[[ -n "${_ENSH_PROTO_KERBEROS_ASREQ:-}" ]] && return 0
readonly _ENSH_PROTO_KERBEROS_ASREQ=1

ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1

readonly KERBEROS_MSGTYPE_AS_REQ=10
readonly KERBEROS_MSGTYPE_AS_REP=11
readonly KERBEROS_MSGTYPE_KRB_ERROR=30

readonly KERBEROS_NAME_NT_PRINCIPAL=1

readonly KERBEROS_PA_ENC_TIMESTAMP=2

readonly KERBEROS_ETYPE_AES128=17
readonly KERBEROS_ETYPE_AES256=18
readonly KERBEROS_ETYPE_RC4_HMAC=23

readonly KERBEROS_ASREQ_DEFAULT_NONCE_HEX="12345678"
readonly KERBEROS_ASREQ_DEFAULT_TILL="20370913024805Z"

readonly -A KERBEROS_ERROR_NAMES=(
    [6]="KDC_ERR_C_PRINCIPAL_UNKNOWN"
    [24]="KDC_ERR_PREAUTH_FAILED"
    [25]="KDC_ERR_PREAUTH_REQUIRED"
    [31]="KRB_AP_ERR_BAD_INTEGRITY"
    [37]="KRB_AP_ERR_SKEW"
    [52]="KRB_ERR_RESPONSE_TOO_BIG"
    [68]="KDC_ERR_WRONG_REALM"
)

# kerberos::asreq::_generalized_time <ascii_time> <var_out>
kerberos::asreq::_generalized_time() {
    local ascii_time="$1"
    local -n _krb_gt_out="$2"
    local time_hex
    hex::from_string "${ascii_time}" time_hex
    asn1::tlv "18" "${time_hex}" _krb_gt_out
}

# kerberos::asreq::_explicit_int <tag_number> <int_value> <var_out>
kerberos::asreq::_explicit_int() {
    local -i tag_number="$1"
    local -i int_value="$2"
    local -n _krb_ei_out="$3"
    local int_tlv
    asn1::integer "$(printf '%X' "${int_value}")" int_tlv
    asn1::context_tag "${tag_number}" "${int_tlv}" _krb_ei_out
}

# kerberos::asreq::_principal_name <name_type> <var_out> <component...>
kerberos::asreq::_principal_name() {
    local -i name_type="$1"
    local -n _krb_pn_out="$2"
    shift 2

    local type_field
    kerberos::asreq::_explicit_int 0 "${name_type}" type_field

    local strings_content=""
    local component component_der
    for component in "$@"; do
        asn1::general_string "${component}" component_der
        strings_content+="${component_der}"
    done

    local strings_seq strings_field
    asn1::sequence "${strings_content}" strings_seq
    asn1::context_tag 1 "${strings_seq}" strings_field

    asn1::sequence "${type_field}${strings_field}" _krb_pn_out
}

# kerberos::asreq::_kdc_options_bitstring <var_out> [bit_number...]
#
# KerberosFlags numérote les options de 0 à 31. Le bit N correspond au bit
# (31 - N) dans le mot 32 bits.
kerberos::asreq::_kdc_options_bitstring() {
    local -n _krb_kdc_out="$1"
    shift

    local -i flags=0
    local -i bit
    for bit in "$@"; do
        flags=$(( flags | (1 << (31 - bit)) ))
    done

    local flags_hex
    hex::from_int "${flags}" 4 flags_hex
    asn1::bit_string "${flags_hex}" _krb_kdc_out
}

# kerberos::asreq::_seq_of_integers <var_out> <int...>
kerberos::asreq::_seq_of_integers() {
    local -n _krb_soi_out="$1"
    shift

    local content=""
    local value value_der
    for value in "$@"; do
        asn1::integer "$(printf '%X' "${value}")" value_der
        content+="${value_der}"
    done
    asn1::sequence "${content}" _krb_soi_out
}

# kerberos::asreq::_parse_explicit <hex> <offset_bytes> <expected_tag> <var_inner_tag> <var_inner_val> <var_next_offset>
kerberos::asreq::_parse_explicit() {
    local hex="${1^^}"
    local -i off="$2"
    local expected_tag="${3^^}"
    local -n _krb_pe_inner_tag="$4"
    local -n _krb_pe_inner_val="$5"
    local -n _krb_pe_next="$6"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${hex}" "${off}" outer_tag outer_len outer_val outer_next
    if [[ -n "${expected_tag}" ]] && [[ "${outer_tag}" != "${expected_tag}" ]]; then
        log::error "kerberos::asreq : tag attendu=0x${expected_tag}, obtenu=0x${outer_tag}"
        return 1
    fi

    asn1::parse_tlv "${outer_val}" 0 _krb_pe_inner_tag _krb_pe_next _krb_pe_inner_val _krb_pe_next
    _krb_pe_next="${outer_next}"
}

# kerberos::asreq::_parse_general_string <hex_tlv> <var_out>
kerberos::asreq::_parse_general_string() {
    local tlv_hex="${1^^}"
    local -n _krb_pgs_out="$2"

    local tag len val next
    asn1::parse_tlv "${tlv_hex}" 0 tag len val next
    case "${tag}" in
        1B|18|04) hex::to_string "${val}" _krb_pgs_out ;;
        *)
            log::error "kerberos::asreq : chaîne ASN.1 attendue, tag=0x${tag}"
            return 1
            ;;
    esac
}

# kerberos::asreq::_parse_principal_name <hex_tlv> <var_out>
kerberos::asreq::_parse_principal_name() {
    local tlv_hex="${1^^}"
    local -n _krb_ppn_out="$2"

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${tlv_hex}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::asreq : PrincipalName attendu, tag=0x${seq_tag}"
        return 1
    fi

    local field_tag field_len field_val field_next
    local -i off=0
    local components=""
    local sep=""

    while (( off < seq_len )); do
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next
        case "${field_tag}" in
            A1)
                local inner_tag inner_len inner_val inner_next
                asn1::parse_tlv "${field_val}" 0 inner_tag inner_len inner_val inner_next
                if [[ "${inner_tag}" != "30" ]]; then
                    log::error "kerberos::asreq : name-string SEQUENCE attendue, tag=0x${inner_tag}"
                    return 1
                fi

                local -i str_off=0
                while (( str_off < inner_len )); do
                    local str_tag str_len str_val str_next
                    asn1::parse_tlv "${inner_val}" "${str_off}" str_tag str_len str_val str_next
                    local str
                    hex::to_string "${str_val}" str
                    components+="${sep}${str}"
                    sep="/"
                    str_off="${str_next}"
                done
                ;;
        esac
        off="${field_next}"
    done

    _krb_ppn_out="${components}"
}

# kerberos::asreq::_parse_encrypted_data <hex_tlv> <var_dict_out>
kerberos::asreq::_parse_encrypted_data() {
    local tlv_hex="${1^^}"
    local -n _krb_ped_out="$2"

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${tlv_hex}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::asreq : EncryptedData attendu, tag=0x${seq_tag}"
        return 1
    fi

    local -i off=0
    while (( off < seq_len )); do
        local field_tag field_len field_val field_next
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next

        local inner_tag inner_len inner_val inner_next
        asn1::parse_tlv "${field_val}" 0 inner_tag inner_len inner_val inner_next

        case "${field_tag}" in
            A0) hex::to_int "${inner_val}" _krb_ped_out[etype] ;;
            A1) hex::to_int "${inner_val}" _krb_ped_out[kvno] ;;
            A2) _krb_ped_out[cipher]="${inner_val}" ;;
        esac

        off="${field_next}"
    done
}

# kerberos::asreq::build <var_out> <username> <realm> [timestamp_hex]
#
# Si timestamp_hex est fourni, il doit correspondre au blob DER déjà encodé
# à placer dans padata-value pour PA-ENC-TIMESTAMP (typiquement EncryptedData).
kerberos::asreq::build() {
    local -n _krb_ab_out="$1"
    local username="$2"
    local realm="${3^^}"
    local timestamp_hex="${4:-}"

    if [[ -n "${timestamp_hex}" ]]; then
        timestamp_hex="${timestamp_hex^^}"
        if ! hex::is_valid "${timestamp_hex}"; then
            log::error "kerberos::asreq::build : timestamp_hex invalide"
            return 1
        fi
    fi

    local pvno_field msgtype_field
    kerberos::asreq::_explicit_int 1 5 pvno_field
    kerberos::asreq::_explicit_int 2 "${KERBEROS_MSGTYPE_AS_REQ}" msgtype_field

    local padata_field=""
    if [[ -n "${timestamp_hex}" ]]; then
        local padata_type padata_value padata_seq padata_set
        kerberos::asreq::_explicit_int 1 "${KERBEROS_PA_ENC_TIMESTAMP}" padata_type
        asn1::octet_string "${timestamp_hex}" padata_value
        asn1::context_tag 2 "${padata_value}" padata_value
        asn1::sequence "${padata_type}${padata_value}" padata_seq
        asn1::sequence "${padata_seq}" padata_set
        asn1::context_tag 3 "${padata_set}" padata_field
    fi

    local kdc_options kdc_field
    kerberos::asreq::_kdc_options_bitstring kdc_options 1 3 8
    asn1::context_tag 0 "${kdc_options}" kdc_field

    local cname principal_cname
    kerberos::asreq::_principal_name "${KERBEROS_NAME_NT_PRINCIPAL}" principal_cname "${username}"
    asn1::context_tag 1 "${principal_cname}" cname

    local realm_der realm_field
    asn1::general_string "${realm}" realm_der
    asn1::context_tag 2 "${realm_der}" realm_field

    local sname principal_sname
    kerberos::asreq::_principal_name "${KERBEROS_NAME_NT_PRINCIPAL}" principal_sname "krbtgt" "${realm}"
    asn1::context_tag 3 "${principal_sname}" sname

    local till_der till_field rtime_der rtime_field
    kerberos::asreq::_generalized_time "${KERBEROS_ASREQ_DEFAULT_TILL}" till_der
    kerberos::asreq::_generalized_time "${KERBEROS_ASREQ_DEFAULT_TILL}" rtime_der
    asn1::context_tag 5 "${till_der}" till_field
    asn1::context_tag 6 "${rtime_der}" rtime_field

    local nonce_der nonce_field
    asn1::integer "${KERBEROS_ASREQ_DEFAULT_NONCE_HEX}" nonce_der
    asn1::context_tag 7 "${nonce_der}" nonce_field

    local etype_seq etype_field
    kerberos::asreq::_seq_of_integers etype_seq \
        "${KERBEROS_ETYPE_RC4_HMAC}" \
        "${KERBEROS_ETYPE_AES256}" \
        "${KERBEROS_ETYPE_AES128}"
    asn1::context_tag 8 "${etype_seq}" etype_field

    local req_body req_body_field req_content
    req_content="${kdc_field}${cname}${realm_field}${sname}${till_field}${rtime_field}${nonce_field}${etype_field}"
    asn1::sequence "${req_content}" req_body
    asn1::context_tag 4 "${req_body}" req_body_field

    local kdc_req as_req_seq
    kdc_req="${pvno_field}${msgtype_field}${padata_field}${req_body_field}"
    asn1::sequence "${kdc_req}" as_req_seq
    asn1::tlv "6A" "${as_req_seq}" _krb_ab_out
}

# kerberos::asreq::parse_asrep <hex_data> <var_dict_out>
kerberos::asreq::parse_asrep() {
    local hex_data="${1^^}"
    local -n _krb_parsed="$2"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${hex_data}" 0 outer_tag outer_len outer_val outer_next
    if [[ "${outer_tag}" != "6B" ]]; then
        log::error "kerberos::asreq::parse_asrep : AS-REP attendu, tag=0x${outer_tag}"
        return 1
    fi

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${outer_val}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::asreq::parse_asrep : SEQUENCE attendue, tag=0x${seq_tag}"
        return 1
    fi

    local -i off=0
    while (( off < seq_len )); do
        local field_tag field_len field_val field_next
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next

        case "${field_tag}" in
            A3)
                kerberos::asreq::_parse_general_string "${field_val}" _krb_parsed[realm] || return 1
                ;;
            A4)
                kerberos::asreq::_parse_principal_name "${field_val}" _krb_parsed[cname] || return 1
                ;;
            A6)
                declare -A enc_part=()
                kerberos::asreq::_parse_encrypted_data "${field_val}" enc_part || return 1
                _krb_parsed[enc_etype]="${enc_part[etype]:-}"
                _krb_parsed[enc_kvno]="${enc_part[kvno]:-}"
                _krb_parsed[enc_cipher]="${enc_part[cipher]:-}"
                ;;
        esac

        off="${field_next}"
    done
}

# kerberos::asreq::parse_krberror <hex_data> <var_dict_out>
kerberos::asreq::parse_krberror() {
    local hex_data="${1^^}"
    local -n _krb_kerr_out="$2"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${hex_data}" 0 outer_tag outer_len outer_val outer_next
    if [[ "${outer_tag}" != "7E" ]]; then
        log::error "kerberos::asreq::parse_krberror : KRB-ERROR attendu, tag=0x${outer_tag}"
        return 1
    fi

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${outer_val}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::asreq::parse_krberror : SEQUENCE attendue, tag=0x${seq_tag}"
        return 1
    fi

    local -i off=0
    _krb_kerr_out[e_text]=""

    while (( off < seq_len )); do
        local field_tag field_len field_val field_next
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next

        case "${field_tag}" in
            A6)
                local inner_tag inner_len inner_val inner_next
                asn1::parse_tlv "${field_val}" 0 inner_tag inner_len inner_val inner_next
                hex::to_int "${inner_val}" _krb_kerr_out[error_code]
                _krb_kerr_out[error_name]="${KERBEROS_ERROR_NAMES[${_krb_kerr_out[error_code]}]:-unknown(${_krb_kerr_out[error_code]})}"
                ;;
            A9)
                kerberos::asreq::_parse_general_string "${field_val}" _krb_kerr_out[realm] || return 1
                ;;
            AB)
                kerberos::asreq::_parse_general_string "${field_val}" _krb_kerr_out[e_text] || return 1
                ;;
        esac

        off="${field_next}"
    done
}
