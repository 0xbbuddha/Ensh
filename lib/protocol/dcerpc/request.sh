#!/usr/bin/env bash
#
# lib/protocol/dcerpc/request.sh — DCE/RPC REQUEST / RESPONSE
#
# Envoie un appel RPC (REQUEST) et parse la réponse (RESPONSE).
# Le stub data est le payload NDR32 spécifique à l'interface appelée.
#
# Structure PDU REQUEST (MS-RPCE §2.2.2.7) :
#
#   Offset  Taille  Champ
#   ──────  ──────  ──────────────────────────────
#    0       1      Version         : 5
#    1       1      VersionMinor    : 0
#    2       1      PacketType      : 0 (REQUEST)
#    3       1      PacketFlags     : FirstFrag(0x01) | LastFrag(0x02)
#    4       4      DataRepresent.  : 0x10000000
#    8       2      FragLength      : taille totale
#   10       2      AuthLength      : 0
#   12       4      CallId          : identifiant de l'appel
#   16       4      AllocHint       : taille totale du stub (hint pour le serveur)
#   20       2      ContextId       : ID du contexte BIND (0)
#   22       2      OpNum           : numéro d'opération (méthode appelée)
#   24+             StubData        : données NDR32 de la requête
#
# Structure PDU RESPONSE (MS-RPCE §2.2.2.8) :
#
#   Offset  Taille  Champ
#   ──────  ──────  ──────────────────────────────
#    0-15           En-tête identique
#   16       4      AllocHint
#   20       2      ContextId
#   22       2      CancelCount (0)
#   24+             StubData de la réponse
#
# Dépendances : core/endian, core/log, protocol/dcerpc/bind
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_DCERPC_REQUEST:-}" ]] && return 0
readonly _ENSH_DCERPC_REQUEST=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/dcerpc/bind

# ── Construction ──────────────────────────────────────────────────────────────

# dcerpc::request::build <var_out> <opnum_int> <stub_hex> <call_id_int>
#                        [context_id_int]
#
# Construit un PDU DCE/RPC REQUEST complet.
# <opnum_int>    : numéro de l'opération (ex: 15 pour NetrShareEnum)
# <stub_hex>     : données NDR32 de l'appel
# <call_id_int>  : doit être incrémenté à chaque appel
dcerpc::request::build() {
    local -n _dcerpc_req_out="$1"
    local -i opnum="$2"
    local stub_hex="${3^^}"
    local -i call_id="${4:-1}"
    local -i context_id="${5:-0}"

    local -i stub_len=$(( ${#stub_hex} / 2 ))
    local -i pdu_len=$(( 24 + stub_len ))

    local opnum_le call_id_le alloc_le ctx_le frag_len_le flags_byte
    endian::le16 "${opnum}"      opnum_le
    endian::le32 "${call_id}"   call_id_le
    endian::le32 "${stub_len}"  alloc_le
    endian::le16 "${context_id}" ctx_le
    endian::le16 "${pdu_len}"   frag_len_le
    printf -v flags_byte '%02X' $(( DCERPC_FLAG_FIRST_FRAG | DCERPC_FLAG_LAST_FRAG ))

    local hdr=""
    hdr+="$(printf '%02X' ${DCERPC_VERSION})"
    hdr+="$(printf '%02X' ${DCERPC_VERSION_MINOR})"
    hdr+="$(printf '%02X' ${DCERPC_PKT_REQUEST})"
    hdr+="${flags_byte}"
    hdr+="${DCERPC_DATA_REPR}"
    hdr+="${frag_len_le}"
    hdr+="0000"                  # AuthLength = 0
    hdr+="${call_id_le}"

    local body=""
    body+="${alloc_le}"          # AllocHint
    body+="${ctx_le}"            # ContextId
    body+="${opnum_le}"          # OpNum
    body+="${stub_hex}"          # StubData

    _dcerpc_req_out="${hdr}${body}"
    log::debug "dcerpc::request : opnum=${opnum} stub=${stub_len}B call_id=${call_id}"
}

# ── Parsing ───────────────────────────────────────────────────────────────────

# dcerpc::request::parse_response <hex_pdu> <var_dict_out>
#
# Parse un PDU RESPONSE ou FAULT.
# Remplit le tableau avec :
#   pkt_type  — type de paquet (2=RESPONSE, 3=FAULT)
#   call_id   — CallId
#   stub      — données NDR32 de la réponse (hex)
#   stub_len  — taille en octets
#   fault_code — code d'erreur si FAULT (sinon absent)
dcerpc::request::parse_response() {
    local pdu="${1^^}"
    local -n _dcerpc_rp_dict="$2"

    local -i pkt_type=$(( 16#${pdu:4:2} ))
    _dcerpc_rp_dict[pkt_type]="${pkt_type}"

    endian::read_le32 "${pdu}" 12 _dcerpc_rp_dict[call_id]
    endian::read_le16 "${pdu}" 8  _dcerpc_frag_len

    if (( pkt_type == DCERPC_PKT_FAULT )); then
        # AllocHint(4) + ContextId(2) + CancelCount(2) + Status(4)
        endian::read_le32 "${pdu}" 24 _dcerpc_rp_dict[fault_code]
        log::error "dcerpc : FAULT code=0x$(printf '%08X' ${_dcerpc_rp_dict[fault_code]})"
        return 1
    fi

    if (( pkt_type != DCERPC_PKT_RESPONSE )); then
        log::error "dcerpc : paquet inattendu type=${pkt_type}"
        return 1
    fi

    # RESPONSE : AllocHint(4) + ContextId(2) + CancelCount(1) + Reserved(1) = 8 octets
    local -i _frag_len="${_dcerpc_frag_len}"
    local -i _stub_off=24
    local -i _stub_len=$(( _frag_len - _stub_off ))

    if (( _stub_len > 0 )); then
        hex::slice "${pdu}" "${_stub_off}" "${_stub_len}" _dcerpc_rp_dict[stub]
    else
        _dcerpc_rp_dict[stub]=""
    fi
    _dcerpc_rp_dict[stub_len]="${_stub_len}"

    log::debug "dcerpc::response : call_id=${_dcerpc_rp_dict[call_id]} stub=${_stub_len}B"
}

# ── Helpers de fragmentation ──────────────────────────────────────────────────

# dcerpc::request::is_last_frag <hex_pdu> → retcode 0 si last frag
dcerpc::request::is_last_frag() {
    local -i flags=$(( 16#${1:6:2} ))
    (( flags & DCERPC_FLAG_LAST_FRAG ))
}

# dcerpc::request::reassemble <var_dict_out> <hex_pdu1> [hex_pdu2...]
#
# Réassemble plusieurs fragments DCE/RPC en un seul stub.
# Remplit le tableau avec stub (hex concaténé) et stub_len.
dcerpc::request::reassemble() {
    local -n _dcerpc_ra_dict="$1"
    shift
    local full_stub=""
    local pdu
    for pdu in "$@"; do
        local -A _frag
        dcerpc::request::parse_response "${pdu}" _frag || return 1
        full_stub+="${_frag[stub]}"
    done
    _dcerpc_ra_dict[stub]="${full_stub}"
    _dcerpc_ra_dict[stub_len]=$(( ${#full_stub} / 2 ))
}
