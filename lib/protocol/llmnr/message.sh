#!/usr/bin/env bash
#
# lib/protocol/llmnr/message.sh — Messages LLMNR (RFC 4795)
#
# LLMNR réutilise le format wire DNS sur UDP/5355, avec des flags légèrement
# différents. Ce module couvre le sous-ensemble utile pour :
#   - construire des requêtes A/AAAA
#   - construire des réponses de poisoning A/AAAA
#   - parser les questions et réponses principales
#

[[ -n "${_ENSH_PROTO_LLMNR_MESSAGE:-}" ]] && return 0
readonly _ENSH_PROTO_LLMNR_MESSAGE=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log

readonly LLMNR_PORT=5355
readonly LLMNR_MCAST_V4="224.0.0.252"
readonly LLMNR_FLAG_RESPONSE=0x8000
readonly LLMNR_QTYPE_A=1
readonly LLMNR_QTYPE_AAAA=28
readonly LLMNR_CLASS_IN=1
readonly LLMNR_DEFAULT_TTL=30

readonly -A _LLMNR_QTYPE_NAMES=(
    [1]="A"
    [28]="AAAA"
)

# llmnr::message::_qtype_from_string <type_str_or_int> <var_out>
llmnr::message::_qtype_from_string() {
    local type_str="${1^^}"
    local -n _llmnr_qts_out="$2"

    case "${type_str}" in
        A|"")
            _llmnr_qts_out="${LLMNR_QTYPE_A}"
            ;;
        AAAA)
            _llmnr_qts_out="${LLMNR_QTYPE_AAAA}"
            ;;
        *)
            if [[ "${type_str}" =~ ^[0-9]+$ ]]; then
                _llmnr_qts_out="${type_str}"
            else
                log::error "llmnr::message : qtype inconnu '${1}'"
                return 1
            fi
            ;;
    esac
}

# llmnr::message::_qtype_name <qtype_int> <var_out>
llmnr::message::_qtype_name() {
    local -i qtype="$1"
    local -n _llmnr_qtn_out="$2"
    _llmnr_qtn_out="${_LLMNR_QTYPE_NAMES[${qtype}]:-${qtype}}"
}

# llmnr::message::_encode_name <name> <var_out>
llmnr::message::_encode_name() {
    local name="${1%.}"
    local -n _llmnr_en_out="$2"

    _llmnr_en_out=""
    if [[ -z "${name}" ]]; then
        _llmnr_en_out="00"
        return 0
    fi

    local IFS='.'
    local label label_hex label_len
    read -r -a _labels <<< "${name}"
    for label in "${_labels[@]}"; do
        label_len="${#label}"
        if (( label_len == 0 || label_len > 63 )); then
            log::error "llmnr::message : label invalide '${label}'"
            return 1
        fi
        local len_hex
        endian::be8 "${label_len}" len_hex
        hex::from_string "${label}" label_hex
        _llmnr_en_out+="${len_hex}${label_hex}"
    done
    _llmnr_en_out+="00"
}

# llmnr::message::_decode_name <hex_msg> <offset_bytes> <var_name_out> <var_next_off_out> [depth]
llmnr::message::_decode_name() {
    local hex_msg="${1^^}"
    local -i off="$2"
    local -n _llmnr_dn_name="$3"
    local -n _llmnr_dn_next="$4"
    local -i depth="${5:-0}"

    if (( depth > 16 )); then
        log::error "llmnr::message : profondeur de compression DNS excessive"
        return 1
    fi

    local byte_hex="${hex_msg:$(( off * 2 )):2}"
    if [[ -z "${byte_hex}" ]]; then
        log::error "llmnr::message : offset hors message"
        return 1
    fi

    local -i first=$(( 16#${byte_hex} ))
    if (( (first & 0xC0) == 0xC0 )); then
        local second_hex="${hex_msg:$(( off * 2 + 2 )):2}"
        local -i ptr=$(( ((first & 0x3F) << 8) | 16#${second_hex} ))
        local _llmnr_dn_ptr_name=""
        local _llmnr_dn_dummy_next
        llmnr::message::_decode_name "${hex_msg}" "${ptr}" _llmnr_dn_ptr_name _llmnr_dn_dummy_next "$(( depth + 1 ))" || return 1
        _llmnr_dn_name="${_llmnr_dn_ptr_name}"
        _llmnr_dn_next=$(( off + 2 ))
        return 0
    fi

    if (( first == 0 )); then
        _llmnr_dn_name=""
        _llmnr_dn_next=$(( off + 1 ))
        return 0
    fi

    local label_hex="${hex_msg:$(( (off + 1) * 2 )):$(( first * 2 ))}"
    local label rest child_next_off
    hex::to_string "${label_hex}" label
    llmnr::message::_decode_name "${hex_msg}" "$(( off + 1 + first ))" rest child_next_off "$(( depth + 1 ))" || return 1
    if [[ -n "${rest}" ]]; then
        _llmnr_dn_name="${label}.${rest}"
    else
        _llmnr_dn_name="${label}"
    fi
    _llmnr_dn_next="${child_next_off}"
}

# llmnr::message::_hex_to_ipv4 <hex_ip> <var_out>
llmnr::message::_hex_to_ipv4() {
    local hex_ip="${1^^}"
    local -n _llmnr_i4_out="$2"

    _llmnr_i4_out="$(( 16#${hex_ip:0:2} )).$(( 16#${hex_ip:2:2} )).$(( 16#${hex_ip:4:2} )).$(( 16#${hex_ip:6:2} ))"
}

# llmnr::message::_hex_to_ipv6 <hex_ip> <var_out>
llmnr::message::_hex_to_ipv6() {
    local hex_ip="${1^^}"
    local -n _llmnr_i6_out="$2"

    _llmnr_i6_out="${hex_ip:0:4}:${hex_ip:4:4}:${hex_ip:8:4}:${hex_ip:12:4}:${hex_ip:16:4}:${hex_ip:20:4}:${hex_ip:24:4}:${hex_ip:28:4}"
}

# llmnr::message::build_query <var_out> <txid_hex> <name> [qtype]
llmnr::message::build_query() {
    local -n _llmnr_bq_out="$1"
    local txid_hex="${2^^}"
    local name="$3"
    local qtype_in="${4:-A}"

    if [[ ${#txid_hex} -ne 4 ]] || ! hex::is_valid "${txid_hex}"; then
        log::error "llmnr::message::build_query : txid invalide"
        return 1
    fi

    local -i qtype
    llmnr::message::_qtype_from_string "${qtype_in}" qtype || return 1

    local qname qtype_hex qclass_hex
    llmnr::message::_encode_name "${name}" qname || return 1
    endian::be16 "${qtype}" qtype_hex
    endian::be16 "${LLMNR_CLASS_IN}" qclass_hex

    _llmnr_bq_out="${txid_hex}"
    _llmnr_bq_out+="0000"      # flags
    _llmnr_bq_out+="0001"      # qdcount
    _llmnr_bq_out+="0000"      # ancount
    _llmnr_bq_out+="0000"      # nscount
    _llmnr_bq_out+="0000"      # arcount
    _llmnr_bq_out+="${qname}${qtype_hex}${qclass_hex}"
}

# llmnr::message::build_response <var_out> <txid_hex> <name> <ip_hex> [ttl]
llmnr::message::build_response() {
    local -n _llmnr_br_out="$1"
    local txid_hex="${2^^}"
    local name="$3"
    local ip_hex="${4^^}"
    local -i ttl="${5:-${LLMNR_DEFAULT_TTL}}"

    if [[ ${#txid_hex} -ne 4 ]] || ! hex::is_valid "${txid_hex}"; then
        log::error "llmnr::message::build_response : txid invalide"
        return 1
    fi
    if ! hex::is_valid "${ip_hex}"; then
        log::error "llmnr::message::build_response : ip_hex invalide"
        return 1
    fi

    local -i qtype rdlen
    case "${#ip_hex}" in
        8)
            qtype="${LLMNR_QTYPE_A}"
            rdlen=4
            ;;
        32)
            qtype="${LLMNR_QTYPE_AAAA}"
            rdlen=16
            ;;
        *)
            log::error "llmnr::message::build_response : taille d'adresse non supportée"
            return 1
            ;;
    esac

    local qname qtype_hex qclass_hex ttl_hex rdlen_hex
    llmnr::message::_encode_name "${name}" qname || return 1
    endian::be16 "${qtype}" qtype_hex
    endian::be16 "${LLMNR_CLASS_IN}" qclass_hex
    endian::be32 "${ttl}" ttl_hex
    endian::be16 "${rdlen}" rdlen_hex

    _llmnr_br_out="${txid_hex}"
    _llmnr_br_out+="8000"      # flags: response/noerror
    _llmnr_br_out+="0001"      # qdcount
    _llmnr_br_out+="0001"      # ancount
    _llmnr_br_out+="0000"      # nscount
    _llmnr_br_out+="0000"      # arcount
    _llmnr_br_out+="${qname}${qtype_hex}${qclass_hex}"
    _llmnr_br_out+="C00C"      # pointer vers le nom de la question
    _llmnr_br_out+="${qtype_hex}${qclass_hex}${ttl_hex}${rdlen_hex}${ip_hex}"
}

# llmnr::message::parse <hex_data> <var_dict_out>
llmnr::message::parse() {
    local hex_data="${1^^}"
    local -n _llmnr_p_out="$2"

    if (( ${#hex_data} < 24 )) || ! hex::is_valid "${hex_data}"; then
        log::error "llmnr::message::parse : message invalide"
        return 1
    fi

    _llmnr_p_out[txid]="${hex_data:0:4}"

    local -i flags qdcount ancount nscount arcount
    endian::read_be16 "${hex_data}" 2 flags
    endian::read_be16 "${hex_data}" 4 qdcount
    endian::read_be16 "${hex_data}" 6 ancount
    endian::read_be16 "${hex_data}" 8 nscount
    endian::read_be16 "${hex_data}" 10 arcount

    _llmnr_p_out[flags]="${flags}"
    _llmnr_p_out[qr]=$(( (flags >> 15) & 0x1 ))
    _llmnr_p_out[opcode]=$(( (flags >> 11) & 0xF ))
    _llmnr_p_out[c]=$(( (flags >> 10) & 0x1 ))
    _llmnr_p_out[tc]=$(( (flags >> 9) & 0x1 ))
    _llmnr_p_out[t]=$(( (flags >> 8) & 0x1 ))
    _llmnr_p_out[rcode]=$(( flags & 0xF ))
    _llmnr_p_out[qdcount]="${qdcount}"
    _llmnr_p_out[ancount]="${ancount}"
    _llmnr_p_out[nscount]="${nscount}"
    _llmnr_p_out[arcount]="${arcount}"

    local -i off=12 i
    for (( i=0; i<qdcount; i++ )); do
        local qname next_off qtype qclass qtype_name
        llmnr::message::_decode_name "${hex_data}" "${off}" qname next_off || return 1
        endian::read_be16 "${hex_data}" "${next_off}" qtype
        endian::read_be16 "${hex_data}" "$(( next_off + 2 ))" qclass
        llmnr::message::_qtype_name "${qtype}" qtype_name

        _llmnr_p_out["question_${i}_name"]="${qname}"
        _llmnr_p_out["question_${i}_type"]="${qtype}"
        _llmnr_p_out["question_${i}_type_name"]="${qtype_name}"
        _llmnr_p_out["question_${i}_class"]="${qclass}"
        if (( i == 0 )); then
            _llmnr_p_out[question_name]="${qname}"
            _llmnr_p_out[qtype]="${qtype}"
            _llmnr_p_out[qtype_name]="${qtype_name}"
            _llmnr_p_out[qclass]="${qclass}"
        fi
        off=$(( next_off + 4 ))
    done

    _llmnr_p_out[answer_count]="${ancount}"
    for (( i=0; i<ancount; i++ )); do
        local rr_name rr_next rr_type rr_class rr_ttl rr_rdlen rr_rdata rr_type_name
        llmnr::message::_decode_name "${hex_data}" "${off}" rr_name rr_next || return 1
        endian::read_be16 "${hex_data}" "${rr_next}" rr_type
        endian::read_be16 "${hex_data}" "$(( rr_next + 2 ))" rr_class
        endian::read_be32 "${hex_data}" "$(( rr_next + 4 ))" rr_ttl
        endian::read_be16 "${hex_data}" "$(( rr_next + 8 ))" rr_rdlen
        hex::slice "${hex_data}" "$(( rr_next + 10 ))" "${rr_rdlen}" rr_rdata
        llmnr::message::_qtype_name "${rr_type}" rr_type_name

        _llmnr_p_out["answer_${i}_name"]="${rr_name}"
        _llmnr_p_out["answer_${i}_type"]="${rr_type}"
        _llmnr_p_out["answer_${i}_type_name"]="${rr_type_name}"
        _llmnr_p_out["answer_${i}_class"]="${rr_class}"
        _llmnr_p_out["answer_${i}_ttl"]="${rr_ttl}"
        _llmnr_p_out["answer_${i}_rdata"]="${rr_rdata}"

        case "${rr_type}" in
            ${LLMNR_QTYPE_A})
                local ip4
                llmnr::message::_hex_to_ipv4 "${rr_rdata}" ip4
                _llmnr_p_out["answer_${i}_ip"]="${ip4}"
                ;;
            ${LLMNR_QTYPE_AAAA})
                local ip6
                llmnr::message::_hex_to_ipv6 "${rr_rdata}" ip6
                _llmnr_p_out["answer_${i}_ip"]="${ip6}"
                ;;
        esac

        off=$(( rr_next + 10 + rr_rdlen ))
    done
}
