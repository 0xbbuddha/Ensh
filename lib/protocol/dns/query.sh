#!/usr/bin/env bash
#
# lib/protocol/dns/query.sh - Resolution DNS pure Bash (RFC 1035)
#
# Construit et envoie des requetes DNS sur le fil sans dependre de
# dig/host/nslookup. Supporte A, AAAA, PTR, MX, TXT, SRV, NS, CNAME.
# Fallback TCP automatique si la reponse UDP est tronquee (TC=1).
#
# API publique :
#   dns::query::build          <var_out> <fqdn> <type_str>
#   dns::query::send_udp       <var_out> <server_ip> <fqdn> <type_str>
#   dns::query::parse_response <hex_data> <var_dict_out>
#
# Exemple :
#   dns::query::send_udp answers "8.8.8.8" "dc01.corp.local" "A"
#   echo "${answers}"   # -> "10.0.0.1"
#
# Dependances : core/endian, core/log, core/hex, transport/tcp
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_BK_PROTO_DNS_QUERY:-}" ]] && return 0
readonly _BK_PROTO_DNS_QUERY=1

bk::import core/endian
bk::import core/log
bk::import core/hex
bk::import transport/tcp

# ── Tables de types ───────────────────────────────────────────────────────────

readonly DNS_TYPE_A=1
readonly DNS_TYPE_NS=2
readonly DNS_TYPE_CNAME=5
readonly DNS_TYPE_SOA=6
readonly DNS_TYPE_PTR=12
readonly DNS_TYPE_MX=15
readonly DNS_TYPE_TXT=16
readonly DNS_TYPE_AAAA=28
readonly DNS_TYPE_SRV=33
readonly DNS_TYPE_ANY=255
readonly DNS_CLASS_IN=1

# RCODE
readonly DNS_RCODE_NOERROR=0
readonly DNS_RCODE_FORMERR=1
readonly DNS_RCODE_SERVFAIL=2
readonly DNS_RCODE_NXDOMAIN=3
readonly DNS_RCODE_NOTIMP=4
readonly DNS_RCODE_REFUSED=5

# ── Helpers internes ──────────────────────────────────────────────────────────

# _dns_type_code <type_str> <var_out>
# Convertit un type DNS en entier.
_dns_type_code() {
    local -n _dtc_out="$2"
    case "${1^^}" in
        A)     _dtc_out=${DNS_TYPE_A}    ;;
        NS)    _dtc_out=${DNS_TYPE_NS}   ;;
        CNAME) _dtc_out=${DNS_TYPE_CNAME} ;;
        SOA)   _dtc_out=${DNS_TYPE_SOA}  ;;
        PTR)   _dtc_out=${DNS_TYPE_PTR}  ;;
        MX)    _dtc_out=${DNS_TYPE_MX}   ;;
        TXT)   _dtc_out=${DNS_TYPE_TXT}  ;;
        AAAA)  _dtc_out=${DNS_TYPE_AAAA} ;;
        SRV)   _dtc_out=${DNS_TYPE_SRV}  ;;
        ANY)   _dtc_out=${DNS_TYPE_ANY}  ;;
        *)     _dtc_out=${DNS_TYPE_A}    ;;
    esac
}

# _dns_type_name <type_int> <var_out>
_dns_type_name() {
    local -n _dtn_out="$2"
    case "$1" in
        1)   _dtn_out="A"     ;;
        2)   _dtn_out="NS"    ;;
        5)   _dtn_out="CNAME" ;;
        6)   _dtn_out="SOA"   ;;
        12)  _dtn_out="PTR"   ;;
        15)  _dtn_out="MX"    ;;
        16)  _dtn_out="TXT"   ;;
        28)  _dtn_out="AAAA"  ;;
        33)  _dtn_out="SRV"   ;;
        255) _dtn_out="ANY"   ;;
        *)   _dtn_out="TYPE$1" ;;
    esac
}

# _dns_encode_name <fqdn> <var_out>
# Encode un FQDN en labels DNS wire (RFC 1035 section 3.1).
_dns_encode_name() {
    local fqdn="${1%.}"  # retirer le point final si present
    local -n _den_out="$2"
    _den_out=""

    if [[ -z "${fqdn}" ]]; then
        _den_out="00"
        return 0
    fi

    local label
    IFS='.' read -ra _dns_labels <<< "${fqdn}"
    for label in "${_dns_labels[@]}"; do
        [[ -z "${label}" ]] && continue
        local len_hex label_hex
        printf -v len_hex '%02X' "${#label}"
        hex::from_string "${label}" label_hex
        _den_out+="${len_hex}${label_hex}"
    done
    _den_out+="00"
}

# _dns_decode_name <hex_msg> <offset_bytes> <var_name_out> <var_next_off_out>
# Decode un nom DNS avec support des pointeurs de compression (RFC 1035 4.1.4).
_dns_decode_name() {
    local msg="${1^^}"
    local -i off="$2"
    local -n _ddn_name="$3"
    local -n _ddn_next="$4"

    _ddn_name=""
    local -i next_set=0
    local first=1

    while true; do
        (( off * 2 + 2 > ${#msg} )) && break

        local -i len=$(( 16#${msg:$(( off * 2 )):2} ))

        if (( (len & 0xC0) == 0xC0 )); then
            # Pointeur de compression : 2 bytes
            local -i ptr=$(( ((len & 0x3F) << 8) | 16#${msg:$(( (off+1)*2 )):2} ))
            if (( !next_set )); then
                _ddn_next=$(( off + 2 ))
                next_set=1
            fi
            off=${ptr}
        elif (( len == 0 )); then
            if (( !next_set )); then
                _ddn_next=$(( off + 1 ))
            fi
            break
        else
            (( off++ ))
            local label_hex="${msg:$(( off*2 )):$(( len*2 ))}"
            local label
            hex::to_string "${label_hex}" label
            [[ "${first}" == "1" ]] || _ddn_name+="."
            _ddn_name+="${label}"
            first=0
            (( off += len ))
        fi
    done
}

# _dns_format_ipv4 <rdata_hex> <var_out>
_dns_format_ipv4() {
    local rdata="${1^^}"
    local -n _dfi_out="$2"
    printf -v _dfi_out '%d.%d.%d.%d' \
        $(( 16#${rdata:0:2} )) $(( 16#${rdata:2:2} )) \
        $(( 16#${rdata:4:2} )) $(( 16#${rdata:6:2} ))
}

# _dns_format_ipv6 <rdata_hex> <var_out>
_dns_format_ipv6() {
    local rdata="${1^^}"
    local -n _dfi6_out="$2"
    printf -v _dfi6_out '%x:%x:%x:%x:%x:%x:%x:%x' \
        $(( 16#${rdata:0:4} ))  $(( 16#${rdata:4:4} )) \
        $(( 16#${rdata:8:4} ))  $(( 16#${rdata:12:4} )) \
        $(( 16#${rdata:16:4} )) $(( 16#${rdata:20:4} )) \
        $(( 16#${rdata:24:4} )) $(( 16#${rdata:28:4} ))
}

# _dns_parse_rdata <type_int> <rdata_hex> <msg_hex> <rdata_offset> <var_out>
# Decode le RDATA d'un enregistrement DNS selon son type.
_dns_parse_rdata() {
    local -i type="$1"
    local rdata="${2^^}"
    local msg="${3^^}"
    local -i rdata_off="$4"
    local -n _dpr_out="$5"

    case "${type}" in
        ${DNS_TYPE_A})
            _dns_format_ipv4 "${rdata}" _dpr_out ;;

        ${DNS_TYPE_AAAA})
            _dns_format_ipv6 "${rdata}" _dpr_out ;;

        ${DNS_TYPE_PTR}|${DNS_TYPE_CNAME}|${DNS_TYPE_NS})
            local _next
            _dns_decode_name "${msg}" "${rdata_off}" _dpr_out _next ;;

        ${DNS_TYPE_MX})
            local -i prio=$(( 16#${rdata:0:4} ))
            local name _next
            _dns_decode_name "${msg}" "$(( rdata_off + 2 ))" name _next
            _dpr_out="${prio} ${name}" ;;

        ${DNS_TYPE_TXT})
            _dpr_out=""
            local -i pos=0 rdlen=$(( ${#rdata} / 2 ))
            while (( pos < rdlen )); do
                local -i slen=$(( 16#${rdata:$(( pos*2 )):2} ))
                (( pos++ ))
                local s_hex="${rdata:$(( pos*2 )):$(( slen*2 ))}"
                local s; hex::to_string "${s_hex}" s
                _dpr_out+="${s}"
                (( pos += slen ))
            done ;;

        ${DNS_TYPE_SRV})
            local -i prio=$(( 16#${rdata:0:4} ))
            local -i weight=$(( 16#${rdata:4:4} ))
            local -i port=$(( 16#${rdata:8:4} ))
            local target _next
            _dns_decode_name "${msg}" "$(( rdata_off + 6 ))" target _next
            _dpr_out="${prio} ${weight} ${port} ${target}" ;;

        *)
            _dpr_out="${rdata}" ;;
    esac
}

# ── API publique ─────────────────────────────────────────────────────────────

# dns::query::build <var_out> <fqdn> <type_str>
#
# Construit un message DNS query (Header + Question section).
# Header : ID(2B) + Flags(2B) + QDCOUNT=1 + ANCOUNT=0 + NSCOUNT=0 + ARCOUNT=0
# Flags standard : RD=1 (recursion desired), tout le reste a 0.
dns::query::build() {
    local -n _dqb_out="$1"
    local fqdn="$2"
    local type_str="${3:-A}"

    # ID aleatoire
    local id_hex
    printf -v id_hex '%04X' "$(( RANDOM & 0xFFFF ))"

    # Flags : QR=0 Opcode=0 AA=0 TC=0 RD=1 RA=0 Z=0 RCODE=0 -> 0x0100
    local flags="0100"

    # Counts
    local qdcount="0001" ancount="0000" nscount="0000" arcount="0000"

    local header="${id_hex}${flags}${qdcount}${ancount}${nscount}${arcount}"

    # Question : QNAME + QTYPE + QCLASS
    local qname
    _dns_encode_name "${fqdn}" qname

    local -i type_code
    _dns_type_code "${type_str}" type_code
    local qtype qclass
    printf -v qtype  '%04X' "${type_code}"
    printf -v qclass '%04X' "${DNS_CLASS_IN}"

    _dqb_out="${header}${qname}${qtype}${qclass}"
}

# dns::query::parse_response <hex_data> <var_dict_out>
#
# Parse un message DNS (query ou response).
# Remplit le dict avec :
#   id            - transaction ID
#   rcode         - code de retour (0=NOERROR, 3=NXDOMAIN...)
#   tc            - bit de troncature (0 ou 1)
#   qr            - 0=query 1=response
#   answer_count  - nombre de reponses
#   answer_N_type - type de la N-ieme reponse (A, AAAA, PTR...)
#   answer_N_value - valeur decoded de la N-ieme reponse
#   answers       - valeurs separees par espace (raccourci)
dns::query::parse_response() {
    local msg="${1^^}"
    local -n _dqpr_dict="$2"

    (( ${#msg} >= 24 )) || return 1  # 12B header minimum

    # -- Header ----------------------------------------------------------------
    local id_hex; hex::slice "${msg}" 0 2 id_hex
    _dqpr_dict[id]="0x${id_hex}"

    local flags_hex; hex::slice "${msg}" 2 2 flags_hex
    local -i flags=$(( 16#${flags_hex} ))

    _dqpr_dict[qr]=$(( (flags >> 15) & 1 ))
    _dqpr_dict[tc]=$(( (flags >> 9) & 1 ))
    _dqpr_dict[rcode]=$(( flags & 0xF ))

    local -i qdcount=$(( 16#${msg:8:4} ))
    local -i ancount=$(( 16#${msg:12:4} ))
    _dqpr_dict[answer_count]="${ancount}"

    # -- Passer les questions --------------------------------------------------
    local -i off=12
    local -i q
    for (( q=0; q<qdcount; q++ )); do
        local _qname _qnext
        _dns_decode_name "${msg}" "${off}" _qname _qnext
        off=$(( _qnext + 4 ))  # sauter QTYPE(2) + QCLASS(2)
    done

    # -- Lire les reponses ----------------------------------------------------
    _dqpr_dict[answers]=""
    local -i a
    for (( a=0; a<ancount; a++ )); do
        # NAME (peut etre un pointeur)
        local _aname _anext
        _dns_decode_name "${msg}" "${off}" _aname _anext
        off="${_anext}"

        (( off * 2 + 20 > ${#msg} )) && break

        local -i atype=$(( 16#${msg:$(( off*2 )):4} ))
        local -i aclass=$(( 16#${msg:$(( off*2+4 )):4} ))
        local -i ttl=$(( 16#${msg:$(( off*2+8 )):8} ))
        local -i rdlength=$(( 16#${msg:$(( off*2+16 )):4} ))
        (( off += 10 ))

        local rdata_hex="${msg:$(( off*2 )):$(( rdlength*2 ))}"
        local rdata_off="${off}"
        (( off += rdlength ))

        local type_name
        _dns_type_name "${atype}" type_name

        local rdata_val
        _dns_parse_rdata "${atype}" "${rdata_hex}" "${msg}" "${rdata_off}" rdata_val

        _dqpr_dict[answer_${a}_type]="${type_name}"
        _dqpr_dict[answer_${a}_value]="${rdata_val}"
        [[ -n "${_dqpr_dict[answers]}" ]] && _dqpr_dict[answers]+=" "
        _dqpr_dict[answers]+="${rdata_val}"

        log::debug "dns : ${_aname} ${ttl}s ${type_name} ${rdata_val}"
    done

    return 0
}

# dns::query::send_udp <var_out> <server_ip> <fqdn> <type_str> [timeout]
#
# Envoie une requete DNS en UDP sur le port 53 et retourne les valeurs
# des enregistrements repondants dans <var_out> (espace-separe).
# Fallback TCP automatique si TC=1 (reponse tronquee).
dns::query::send_udp() {
    local -n _dqs_out="$1"
    local server_ip="$2"
    local fqdn="$3"
    local type_str="${4:-A}"
    local -i timeout="${5:-5}"

    _dqs_out=""

    local query_hex
    dns::query::build query_hex "${fqdn}" "${type_str}"

    # -- Envoi UDP via nc ------------------------------------------------------
    local resp_hex=""

    if command -v nc &>/dev/null; then
        resp_hex=$(
            printf '%s' "${query_hex}" | xxd -r -p \
            | nc -u -w"${timeout}" "${server_ip}" 53 2>/dev/null \
            | od -An -tx1 -v | tr -d ' \n' | tr 'a-f' 'A-F'
        )
    fi

    # Fallback via udp::send_recv si nc echoue ou indisponible
    if [[ -z "${resp_hex}" ]]; then
        udp::send_recv "${server_ip}" 53 "${query_hex}" resp_hex "${timeout}" 512 || true
    fi

    [[ -z "${resp_hex}" ]] && { log::error "dns : pas de reponse de ${server_ip}"; return 1; }

    # -- Verifier TC (troncature) -> fallback TCP ------------------------------
    local -A _resp_dict
    dns::query::parse_response "${resp_hex}" _resp_dict || return 1

    if (( _resp_dict[tc] == 1 )); then
        log::debug "dns : reponse UDP tronquee, fallback TCP"
        _dns_query_tcp _resp_dict "${server_ip}" "${query_hex}" "${timeout}" || return 1
    fi

    local -i rcode="${_resp_dict[rcode]:-3}"
    if (( rcode != DNS_RCODE_NOERROR )); then
        case "${rcode}" in
            ${DNS_RCODE_NXDOMAIN})  log::debug "dns : NXDOMAIN pour ${fqdn}" ;;
            ${DNS_RCODE_SERVFAIL})  log::error "dns : SERVFAIL de ${server_ip}" ;;
            ${DNS_RCODE_REFUSED})   log::error "dns : REFUSED de ${server_ip}" ;;
            *) log::error "dns : RCODE=${rcode}" ;;
        esac
        return 1
    fi

    _dqs_out="${_resp_dict[answers]:-}"
    log::debug "dns : ${fqdn} ${type_str} -> ${_dqs_out}"
}

# _dns_query_tcp <dict_name_ref> <server_ip> <query_hex> <timeout>
# Fallback TCP pour les reponses tronquees (DNS over TCP, RFC 1035 4.2.2).
_dns_query_tcp() {
    local -n _dqt_dict="$1"
    local server_ip="$2"
    local query_hex="${3^^}"
    local -i timeout="$4"

    local handle
    tcp::connect "${server_ip}" 53 handle "${timeout}" || return 1

    # DNS/TCP : prefixe 2 octets = longueur du message
    local -i qlen=$(( ${#query_hex} / 2 ))
    local len_hex; printf -v len_hex '%04X' "${qlen}"
    tcp::send "${handle}" "${len_hex}${query_hex}" || { tcp::close "${handle}" 2>/dev/null; return 1; }

    # Lire la longueur de la reponse (2B)
    local len_resp
    tcp::recv "${handle}" 2 len_resp "${timeout}" || { tcp::close "${handle}" 2>/dev/null; return 1; }
    local -i rlen=$(( 16#${len_resp} ))

    # Lire la reponse
    local resp_hex
    tcp::recv "${handle}" "${rlen}" resp_hex "${timeout}" || { tcp::close "${handle}" 2>/dev/null; return 1; }
    tcp::close "${handle}" 2>/dev/null

    dns::query::parse_response "${resp_hex}" _dqt_dict
}
