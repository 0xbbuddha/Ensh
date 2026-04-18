#!/usr/bin/env bash
#
# lib/protocol/kerberos/tgsreq.sh — Kerberos TGS-REQ / TGS-REP
#
# Sous-ensemble Kerberos utile pour :
#   - construire un TGS-REQ à partir d'un TGT (AS-REP/TGS-REP complet)
#   - parser un TGS-REP pour récupérer le ticket de service exploitable
#     en Kerberoast
#

[[ -n "${_ENSH_PROTO_KERBEROS_TGSREQ:-}" ]] && return 0
readonly _ENSH_PROTO_KERBEROS_TGSREQ=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1
ensh::import crypto/hmac_md5
ensh::import crypto/rc4
ensh::import protocol/kerberos/asreq

readonly KERBEROS_MSGTYPE_TGS_REQ=12
readonly KERBEROS_MSGTYPE_TGS_REP=13
readonly KERBEROS_MSGTYPE_AP_REQ=14

readonly KERBEROS_PA_TGS_REQ=1

readonly KERBEROS_TGSREQ_DEFAULT_CUSEC=654321
readonly KERBEROS_TGSREQ_DEFAULT_CONFOUNDER_HEX="1122334455667788"

# kerberos::tgsreq::_utc_now <var_out>
kerberos::tgsreq::_utc_now() {
    local -n _krb_tn_out="$1"
    _krb_tn_out="$(date -u +%Y%m%d%H%M%SZ 2>/dev/null || printf '%s' "${KERBEROS_ASREQ_DEFAULT_TILL}")"
}

# kerberos::tgsreq::_utc_plus_one_day <var_out>
kerberos::tgsreq::_utc_plus_one_day() {
    local -n _krb_tpd_out="$1"
    _krb_tpd_out="$(date -u -d '+1 day' +%Y%m%d%H%M%SZ 2>/dev/null || printf '%s' "${KERBEROS_ASREQ_DEFAULT_TILL}")"
}

# kerberos::tgsreq::_current_cusec <var_out>
kerberos::tgsreq::_current_cusec() {
    local -n _krb_tc_out="$1"
    local ns
    ns="$(date -u +%N 2>/dev/null || printf '000000000')"
    ns="${ns%%[^0-9]*}"
    ns="${ns:0:6}"
    [[ -z "${ns}" ]] && ns="${KERBEROS_TGSREQ_DEFAULT_CUSEC}"
    _krb_tc_out=$(( 10#${ns} ))
}

# kerberos::tgsreq::_random_hex <nbytes> <var_out>
kerberos::tgsreq::_random_hex() {
    local -i nbytes="$1"
    local -n _krb_trh_out="$2"

    if command -v openssl >/dev/null 2>&1; then
        _krb_trh_out="$(
            openssl rand -hex "${nbytes}" 2>/dev/null | tr -d '\n' | tr '[:lower:]' '[:upper:]'
        )"
    else
        _krb_trh_out="$(
            head -c "${nbytes}" /dev/urandom 2>/dev/null | xxd -p -u | tr -d '\n'
        )"
    fi

    [[ -n "${_krb_trh_out}" ]]
}

# kerberos::tgsreq::_rc4_usage_str <usage_int> <var_out>
kerberos::tgsreq::_rc4_usage_str() {
    local -i usage="$1"
    local -n _krb_rus_out="$2"

    case "${usage}" in
        3) usage=8 ;;
        23) usage=13 ;;
    esac

    endian::le32 "${usage}" _krb_rus_out
}

# kerberos::tgsreq::_rc4_hmac_encrypt <key_hex> <usage_int> <plaintext_hex> <confounder_hex> <var_out>
kerberos::tgsreq::_rc4_hmac_encrypt() {
    local key_hex="${1^^}"
    local -i usage="$2"
    local plaintext_hex="${3^^}"
    local confounder_hex="${4^^}"
    local -n _krb_rce_out="$5"

    if [[ ${#key_hex} -ne 32 ]] || ! hex::is_valid "${key_hex}"; then
        log::error "kerberos::tgsreq : clé RC4-HMAC invalide"
        return 1
    fi
    if [[ ${#confounder_hex} -ne 16 ]] || ! hex::is_valid "${confounder_hex}"; then
        log::error "kerberos::tgsreq : confounder RC4-HMAC invalide"
        return 1
    fi
    if ! hex::is_valid "${plaintext_hex}"; then
        log::error "kerberos::tgsreq : plaintext RC4-HMAC invalide"
        return 1
    fi

    local usage_hex ki checksum ke ciphertext
    kerberos::tgsreq::_rc4_usage_str "${usage}" usage_hex
    hmac_md5::compute "${key_hex}" "${usage_hex}" ki || return 1
    hmac_md5::compute "${ki}" "${confounder_hex}${plaintext_hex}" checksum || return 1
    hmac_md5::compute "${ki}" "${checksum}" ke || return 1
    rc4::crypt "${ke}" "${confounder_hex}${plaintext_hex}" ciphertext || return 1
    _krb_rce_out="${checksum}${ciphertext}"
}

# kerberos::tgsreq::_parse_kdc_rep <hex_data> <var_dict_out>
#
# Accepte un AS-REP (0x6B) ou un TGS-REP (0x6D).
kerberos::tgsreq::_parse_kdc_rep() {
    local hex_data="${1^^}"
    local -n _krb_tpr_out="$2"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${hex_data}" 0 outer_tag outer_len outer_val outer_next
    case "${outer_tag}" in
        6B|6D) ;;
        *)
            log::error "kerberos::tgsreq : KDC-REP attendu, tag=0x${outer_tag}"
            return 1
            ;;
    esac

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${outer_val}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::tgsreq : SEQUENCE attendue dans le KDC-REP, tag=0x${seq_tag}"
        return 1
    fi

    local -i off=0
    while (( off < seq_len )); do
        local field_tag field_len field_val field_next
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next

        case "${field_tag}" in
            A3)
                kerberos::asreq::_parse_general_string "${field_val}" _krb_tpr_out[realm] || return 1
                ;;
            A4)
                kerberos::asreq::_parse_principal_name "${field_val}" _krb_tpr_out[cname] || return 1
                ;;
            A5)
                _krb_tpr_out[ticket_tlv]="${field_val}"
                ;;
            A6)
                declare -A enc_part=()
                kerberos::asreq::_parse_encrypted_data "${field_val}" enc_part || return 1
                _krb_tpr_out[enc_etype]="${enc_part[etype]:-}"
                ;;
        esac

        off="${field_next}"
    done

    [[ -n "${_krb_tpr_out[realm]:-}" && -n "${_krb_tpr_out[cname]:-}" && -n "${_krb_tpr_out[ticket_tlv]:-}" ]]
}

# kerberos::tgsreq::_parse_ticket <ticket_tlv_hex> <var_dict_out>
kerberos::tgsreq::_parse_ticket() {
    local ticket_tlv="${1^^}"
    local -n _krb_tpt_out="$2"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${ticket_tlv}" 0 outer_tag outer_len outer_val outer_next
    if [[ "${outer_tag}" != "61" ]]; then
        log::error "kerberos::tgsreq : Ticket attendu, tag=0x${outer_tag}"
        return 1
    fi

    local seq_tag seq_len seq_val seq_next
    asn1::parse_tlv "${outer_val}" 0 seq_tag seq_len seq_val seq_next
    if [[ "${seq_tag}" != "30" ]]; then
        log::error "kerberos::tgsreq : SEQUENCE attendue dans Ticket, tag=0x${seq_tag}"
        return 1
    fi

    local -i off=0
    while (( off < seq_len )); do
        local field_tag field_len field_val field_next
        asn1::parse_tlv "${seq_val}" "${off}" field_tag field_len field_val field_next

        case "${field_tag}" in
            A1)
                kerberos::asreq::_parse_general_string "${field_val}" _krb_tpt_out[realm] || return 1
                ;;
            A2)
                kerberos::asreq::_parse_principal_name "${field_val}" _krb_tpt_out[sname] || return 1
                ;;
            A3)
                declare -A enc_part=()
                kerberos::asreq::_parse_encrypted_data "${field_val}" enc_part || return 1
                _krb_tpt_out[etype]="${enc_part[etype]:-}"
                _krb_tpt_out[kvno]="${enc_part[kvno]:-}"
                _krb_tpt_out[cipher]="${enc_part[cipher]:-}"
                ;;
        esac

        off="${field_next}"
    done
}

# kerberos::tgsreq::_principal_from_slash <principal_slash> <var_out>
kerberos::tgsreq::_principal_from_slash() {
    local principal_slash="$1"
    local -n _krb_tps_out="$2"

    local -a components=()
    IFS='/' read -r -a components <<< "${principal_slash}"
    kerberos::asreq::_principal_name "${KERBEROS_NAME_NT_PRINCIPAL}" _krb_tps_out "${components[@]}"
}

# kerberos::tgsreq::_build_ap_req <var_out> <ticket_tlv> <client_realm> <client_cname> <session_key_hex>
kerberos::tgsreq::_build_ap_req() {
    local -n _krb_tba_out="$1"
    local ticket_tlv="${2^^}"
    local client_realm="$3"
    local client_cname="$4"
    local session_key_hex="${5^^}"

    local ctime="${ENSH_KRB5_TGSREQ_CTIME:-}"
    [[ -z "${ctime}" ]] && kerberos::tgsreq::_utc_now ctime

    local cusec="${ENSH_KRB5_TGSREQ_CUSEC:-}"
    [[ -z "${cusec}" ]] && kerberos::tgsreq::_current_cusec cusec

    local confounder_hex="${ENSH_KRB5_TGSREQ_CONFOUNDER_HEX:-}"
    [[ -z "${confounder_hex}" ]] && kerberos::tgsreq::_random_hex 8 confounder_hex
    confounder_hex="${confounder_hex^^}"

    local auth_vno auth_realm auth_name auth_cusec_int auth_ctime auth_seq
    kerberos::asreq::_explicit_int 0 5 auth_vno
    local realm_der
    asn1::general_string "${client_realm}" realm_der
    asn1::context_tag 1 "${realm_der}" auth_realm

    local principal_name
    kerberos::tgsreq::_principal_from_slash "${client_cname}" principal_name
    asn1::context_tag 2 "${principal_name}" auth_name

    kerberos::asreq::_explicit_int 4 "${cusec}" auth_cusec_int
    kerberos::asreq::_generalized_time "${ctime}" auth_ctime
    asn1::context_tag 5 "${auth_ctime}" auth_ctime

    asn1::sequence "${auth_vno}${auth_realm}${auth_name}${auth_cusec_int}${auth_ctime}" auth_seq
    local authenticator_tlv
    asn1::tlv "62" "${auth_seq}" authenticator_tlv

    local authenticator_cipher
    kerberos::tgsreq::_rc4_hmac_encrypt "${session_key_hex}" 7 "${authenticator_tlv}" "${confounder_hex}" authenticator_cipher || return 1

    local ap_pvno ap_msgtype ap_options ap_ticket ap_auth_etype ap_auth_cipher ap_auth_seq ap_auth_field
    kerberos::asreq::_explicit_int 0 5 ap_pvno
    kerberos::asreq::_explicit_int 1 "${KERBEROS_MSGTYPE_AP_REQ}" ap_msgtype

    local opts_bitstr
    kerberos::asreq::_kdc_options_bitstring opts_bitstr
    asn1::context_tag 2 "${opts_bitstr}" ap_options
    asn1::context_tag 3 "${ticket_tlv}" ap_ticket

    kerberos::asreq::_explicit_int 0 "${KERBEROS_ETYPE_RC4_HMAC}" ap_auth_etype
    local cipher_octet
    asn1::octet_string "${authenticator_cipher}" cipher_octet
    asn1::context_tag 2 "${cipher_octet}" ap_auth_cipher
    asn1::sequence "${ap_auth_etype}${ap_auth_cipher}" ap_auth_seq
    asn1::context_tag 4 "${ap_auth_seq}" ap_auth_field

    local ap_seq
    asn1::sequence "${ap_pvno}${ap_msgtype}${ap_options}${ap_ticket}${ap_auth_field}" ap_seq
    asn1::tlv "6E" "${ap_seq}" _krb_tba_out
}

# kerberos::tgsreq::build <var_out> <tgt_hex> <session_key_hex> <spn>
#
# <tgt_hex> doit être un AS-REP ou TGS-REP complet contenant le TGT.
# Le builder supporte actuellement les TGT dont l'enc-part client est en RC4-HMAC.
kerberos::tgsreq::build() {
    local -n _krb_tb_out="$1"
    local tgt_hex="${2^^}"
    local session_key_hex="${3^^}"
    local spn_input="$4"

    if ! hex::is_valid "${tgt_hex}"; then
        log::error "kerberos::tgsreq::build : tgt_hex invalide"
        return 1
    fi
    if ! hex::is_valid "${session_key_hex}"; then
        log::error "kerberos::tgsreq::build : session_key_hex invalide"
        return 1
    fi

    declare -A tgt=()
    kerberos::tgsreq::_parse_kdc_rep "${tgt_hex}" tgt || return 1

    if [[ "${tgt[enc_etype]:-}" != "${KERBEROS_ETYPE_RC4_HMAC}" ]]; then
        log::error "kerberos::tgsreq::build : etype TGT ${tgt[enc_etype]:-inconnu} non supporté (RC4-HMAC uniquement pour l'instant)"
        return 1
    fi

    local spn="${spn_input}"
    local request_realm="${tgt[realm]}"
    if [[ "${spn}" == *@* ]]; then
        request_realm="${spn##*@}"
        spn="${spn%@*}"
    fi
    request_realm="${request_realm^^}"

    local spn_principal
    kerberos::tgsreq::_principal_from_slash "${spn}" spn_principal

    local ap_req
    kerberos::tgsreq::_build_ap_req ap_req "${tgt[ticket_tlv]}" "${tgt[realm]}" "${tgt[cname]}" "${session_key_hex}" || return 1

    local pvno_field msgtype_field
    kerberos::asreq::_explicit_int 1 5 pvno_field
    kerberos::asreq::_explicit_int 2 "${KERBEROS_MSGTYPE_TGS_REQ}" msgtype_field

    local padata_type padata_value padata_seq padata_list padata_field
    kerberos::asreq::_explicit_int 1 "${KERBEROS_PA_TGS_REQ}" padata_type
    asn1::octet_string "${ap_req}" padata_value
    asn1::context_tag 2 "${padata_value}" padata_value
    asn1::sequence "${padata_type}${padata_value}" padata_seq
    asn1::sequence "${padata_seq}" padata_list
    asn1::context_tag 3 "${padata_list}" padata_field

    local till="${ENSH_KRB5_TGSREQ_TILL:-}"
    [[ -z "${till}" ]] && kerberos::tgsreq::_utc_plus_one_day till

    local nonce_hex="${ENSH_KRB5_TGSREQ_NONCE_HEX:-}"
    [[ -z "${nonce_hex}" ]] && kerberos::tgsreq::_random_hex 4 nonce_hex
    nonce_hex="${nonce_hex^^}"
    if ! hex::is_valid "${nonce_hex}"; then
        log::error "kerberos::tgsreq::build : nonce hex invalide"
        return 1
    fi

    local kdc_options kdc_field realm_der realm_field sname_field till_der till_field nonce_int nonce_field etype_seq etype_field
    kerberos::asreq::_kdc_options_bitstring kdc_options 1 8 15 27
    asn1::context_tag 0 "${kdc_options}" kdc_field

    asn1::general_string "${request_realm}" realm_der
    asn1::context_tag 2 "${realm_der}" realm_field
    asn1::context_tag 3 "${spn_principal}" sname_field

    kerberos::asreq::_generalized_time "${till}" till_der
    asn1::context_tag 5 "${till_der}" till_field

    local nonce_der
    asn1::integer "${nonce_hex}" nonce_der
    asn1::context_tag 7 "${nonce_der}" nonce_field

    kerberos::asreq::_seq_of_integers etype_seq \
        "${KERBEROS_ETYPE_RC4_HMAC}" \
        "${KERBEROS_ETYPE_AES256}" \
        "${KERBEROS_ETYPE_AES128}"
    asn1::context_tag 8 "${etype_seq}" etype_field

    local req_body req_body_field req_content seq
    req_content="${kdc_field}${realm_field}${sname_field}${till_field}${nonce_field}${etype_field}"
    asn1::sequence "${req_content}" req_body
    asn1::context_tag 4 "${req_body}" req_body_field

    asn1::sequence "${pvno_field}${msgtype_field}${padata_field}${req_body_field}" seq
    asn1::tlv "6C" "${seq}" _krb_tb_out
}

# kerberos::tgsreq::parse_tgsrep <hex_data> <var_dict_out>
kerberos::tgsreq::parse_tgsrep() {
    local hex_data="${1^^}"
    local -n _krb_ptr_out="$2"

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${hex_data}" 0 outer_tag outer_len outer_val outer_next
    if [[ "${outer_tag}" != "6D" ]]; then
        log::error "kerberos::tgsreq::parse_tgsrep : TGS-REP attendu, tag=0x${outer_tag}"
        return 1
    fi

    declare -A rep=()
    kerberos::tgsreq::_parse_kdc_rep "${hex_data}" rep || return 1
    declare -A ticket=()
    kerberos::tgsreq::_parse_ticket "${rep[ticket_tlv]}" ticket || return 1

    _krb_ptr_out[realm]="${ticket[realm]:-${rep[realm]:-}}"
    _krb_ptr_out[sname]="${ticket[sname]:-}"
    _krb_ptr_out[ticket_etype]="${ticket[etype]:-}"
    _krb_ptr_out[ticket_kvno]="${ticket[kvno]:-}"
    _krb_ptr_out[ticket_cipher]="${ticket[cipher]:-}"
    _krb_ptr_out[ticket_tlv]="${rep[ticket_tlv]}"
}
