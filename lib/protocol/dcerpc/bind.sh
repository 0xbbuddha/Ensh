#!/usr/bin/env bash
#
# lib/protocol/dcerpc/bind.sh — DCE/RPC BIND / BIND_ACK
#
# Établit une association DCE/RPC avec une interface MSRPC sur un named pipe.
# Le BIND envoie la liste des interfaces souhaitées (context list) et le
# serveur répond avec BIND_ACK indiquant quelles interfaces sont acceptées.
#
# Structure PDU DCE/RPC (MS-RPCE §2.2.2.4) :
#
#   Offset  Taille  Champ
#   ──────  ──────  ──────────────────────────────
#    0       1      Version         : 5
#    1       1      VersionMinor    : 0
#    2       1      PacketType      : BIND=11 / BIND_ACK=12 / BIND_NAK=13
#    3       1      PacketFlags     : FirstFrag(0x01) | LastFrag(0x02)
#    4       4      DataRepresent.  : 0x10000000 (LE, ASCII, IEEE float)
#    8       2      FragLength      : taille totale du PDU
#   10       2      AuthLength      : 0 (pas d'auth au niveau RPCE)
#   12       4      CallId          : identifiant de l'appel (LE32)
#   16       2      MaxSendFrag     : 4280 (taille max d'un fragment envoyé)
#   18       2      MaxRecvFrag     : 4280 (taille max d'un fragment reçu)
#   20       4      AssocGroupId    : 0 (nouveau groupe d'association)
#   24       1      NumCtxItems     : nombre de contextes (interfaces)
#   25       3      Reserved
#   28+             ContextItems    : liste de ContextElement
#
# ContextElement :
#   ContextId     : LE16 — ID du contexte (0, 1, 2...)
#   NumTransItems : LE16 — nombre de syntaxes de transfert (toujours 1)
#   InterfaceUUID : 16 octets — UUID de l'interface cible
#   InterfaceVer  : LE16 — version majeure
#   InterfaceVerM : LE16 — version mineure
#   TransferUUID  : 16 octets — UUID syntaxe de transfert (NDR32 ou NDR64)
#   TransferVer   : LE32 — version syntaxe (2 pour NDR32)
#
# NDR32 Transfer Syntax UUID : 8a885d04-1ceb-11c9-9fe8-08002b104860 v2
#
# Dépendances : core/endian, core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_DCERPC_BIND:-}" ]] && return 0
readonly _ENSH_DCERPC_BIND=1

ensh::import core/endian
ensh::import core/log

# ── Constantes DCE/RPC ────────────────────────────────────────────────────────

readonly DCERPC_VERSION=5
readonly DCERPC_VERSION_MINOR=0

readonly DCERPC_PKT_BIND=11
readonly DCERPC_PKT_BIND_ACK=12
readonly DCERPC_PKT_BIND_NAK=13
readonly DCERPC_PKT_REQUEST=0
readonly DCERPC_PKT_RESPONSE=2
readonly DCERPC_PKT_FAULT=3

readonly DCERPC_FLAG_FIRST_FRAG=0x01
readonly DCERPC_FLAG_LAST_FRAG=0x02
readonly DCERPC_FLAG_OBJECT_UUID=0x80

# DataRepresentation : little-endian, ASCII, IEEE float
readonly DCERPC_DATA_REPR="10000000"

readonly DCERPC_MAX_FRAG=4280

# NDR32 Transfer Syntax : 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
# UUID encodé en LE (les 3 premiers groupes sont LE, les 2 derniers BE)
readonly DCERPC_NDR32_UUID="04 5d 88 8a  eb 1c  c9 11  9f e8  08 00 2b 10 48 60"
readonly DCERPC_NDR32_UUID_HEX="045D888AEB1CC9119FE808002B104860"
readonly DCERPC_NDR32_VER="02000000"   # version 2 en LE32

# Résultats BIND_ACK
readonly DCERPC_RESULT_ACCEPT=0
readonly DCERPC_RESULT_REJECT=1
readonly DCERPC_RESULT_PROVIDER_REJECT=2

# ── Helpers UUID ──────────────────────────────────────────────────────────────

# dcerpc::uuid::encode <uuid_str> <var_out>
#
# Encode un UUID canonique "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# en 16 octets selon l'encodage DCE/RPC (3 premiers groupes LE, 2 derniers BE).
#
# Ex: 4B324FC8-1670-01D3-1278-5A47BF6EE188 (SRVSVC)
#     → C84F324B  7016  D301  1278  5A47BF6EE188
dcerpc::uuid::encode() {
    local uuid="${1^^}"
    local -n _dcerpc_uuid_out="$2"

    # Supprimer les tirets
    uuid="${uuid//-/}"
    # a1b2c3d4 e5f6 0708 090a 0b0c0d0e0f10
    # groupes : [0-7] [8-11] [12-15] [16-19] [20-31]

    local g1="${uuid:0:8}"   # 4 octets LE
    local g2="${uuid:8:4}"   # 2 octets LE
    local g3="${uuid:12:4}"  # 2 octets LE
    local g4="${uuid:16:4}"  # 2 octets BE (pas de swap)
    local g5="${uuid:20:12}" # 6 octets BE (pas de swap)

    # g1 : swap 4 octets en LE
    local g1_le
    endian::le32 "$(( 16#${g1} ))" g1_le

    # g2 : swap 2 octets en LE
    local g2_le
    endian::le16 "$(( 16#${g2} ))" g2_le

    # g3 : swap 2 octets en LE
    local g3_le
    endian::le16 "$(( 16#${g3} ))" g3_le

    _dcerpc_uuid_out="${g1_le}${g2_le}${g3_le}${g4}${g5}"
}

# ── Interfaces MSRPC connues ──────────────────────────────────────────────────

# SRVSVC — Server Service (enum shares, sessions, connexions)
readonly DCERPC_IF_SRVSVC_UUID="4B324FC8-1670-01D3-1278-5A47BF6EE188"
readonly DCERPC_IF_SRVSVC_VER_MAJ=3
readonly DCERPC_IF_SRVSVC_VER_MIN=0

# SAMR — Security Account Manager Remote
readonly DCERPC_IF_SAMR_UUID="12345778-1234-ABCD-EF00-0123456789AC"
readonly DCERPC_IF_SAMR_VER_MAJ=1
readonly DCERPC_IF_SAMR_VER_MIN=0

# LSARPC — Local Security Authority Remote Protocol
readonly DCERPC_IF_LSARPC_UUID="12345778-1234-ABCD-EF00-0123456789AB"
readonly DCERPC_IF_LSARPC_VER_MAJ=0
readonly DCERPC_IF_LSARPC_VER_MIN=0

# ── Construction ──────────────────────────────────────────────────────────────

# dcerpc::bind::build <var_out> <if_uuid_str> <if_ver_maj> <if_ver_min> <call_id>
#
# Construit un PDU DCE/RPC BIND avec un seul contexte (NDR32).
dcerpc::bind::build() {
    local -n _dcerpc_bind_out="$1"
    local if_uuid_str="$2"
    local -i if_ver_maj="$3"
    local -i if_ver_min="$4"
    local -i call_id="${5:-1}"

    # Encoder l'UUID de l'interface
    local if_uuid_hex
    dcerpc::uuid::encode "${if_uuid_str}" if_uuid_hex

    local if_ver_le if_verm_le call_id_le max_send_le max_recv_le
    endian::le16 "${if_ver_maj}"    if_ver_le
    endian::le16 "${if_ver_min}"    if_verm_le
    endian::le32 "${call_id}"       call_id_le
    endian::le16 "${DCERPC_MAX_FRAG}" max_send_le
    endian::le16 "${DCERPC_MAX_FRAG}" max_recv_le

    # ── ContextElement ────────────────────────────────────────────────────────
    local ctx=""
    ctx+="0000"              # ContextId = 0
    ctx+="0100"              # NumTransItems = 1
    ctx+="${if_uuid_hex}"    # InterfaceUUID (16 octets)
    ctx+="${if_ver_le}"      # InterfaceVersion (majeure)
    ctx+="${if_verm_le}"     # InterfaceVersion (mineure)
    ctx+="${DCERPC_NDR32_UUID_HEX}" # TransferSyntax UUID (NDR32)
    ctx+="${DCERPC_NDR32_VER}"      # TransferSyntax version

    # ── Corps du BIND ─────────────────────────────────────────────────────────
    local body=""
    body+="${max_send_le}"   # MaxSendFrag
    body+="${max_recv_le}"   # MaxRecvFrag
    body+="00000000"         # AssocGroupId = 0
    body+="01"               # NumCtxItems = 1
    body+="000000"           # Padding
    body+="${ctx}"           # ContextElement

    # ── En-tête PDU ───────────────────────────────────────────────────────────
    local -i pdu_len=$(( 16 + ${#body} / 2 ))
    local frag_len_le flags_byte
    endian::le16 "${pdu_len}" frag_len_le
    printf -v flags_byte '%02X' $(( DCERPC_FLAG_FIRST_FRAG | DCERPC_FLAG_LAST_FRAG ))

    local hdr=""
    hdr+="$(printf '%02X' ${DCERPC_VERSION})"       # Version = 5
    hdr+="$(printf '%02X' ${DCERPC_VERSION_MINOR})" # VersionMinor = 0
    hdr+="$(printf '%02X' ${DCERPC_PKT_BIND})"      # PacketType = 11
    hdr+="${flags_byte}"                             # PacketFlags
    hdr+="${DCERPC_DATA_REPR}"                       # DataRepresentation
    hdr+="${frag_len_le}"                            # FragLength
    hdr+="0000"                                      # AuthLength = 0
    hdr+="${call_id_le}"                             # CallId

    _dcerpc_bind_out="${hdr}${body}"
    log::debug "dcerpc::bind : if=${if_uuid_str} v${if_ver_maj}.${if_ver_min} call_id=${call_id} len=${pdu_len}B"
}

# ── Parsing ───────────────────────────────────────────────────────────────────

# dcerpc::bind::parse_ack <hex_pdu> <var_dict_out>
#
# Parse un PDU BIND_ACK.
# Remplit le tableau avec :
#   pkt_type   — type de paquet (12=ACK, 13=NAK)
#   call_id    — CallId
#   assoc_grp  — AssocGroupId (à réutiliser pour les appels suivants)
#   result     — résultat du premier contexte (0=accept)
#   max_recv   — MaxRecvFrag du serveur
dcerpc::bind::parse_ack() {
    local pdu="${1^^}"
    local -n _dcerpc_ba_dict="$2"

    # En-tête : 16 octets
    local -i pkt_type=$(( 16#${pdu:4:2} ))
    _dcerpc_ba_dict[pkt_type]="${pkt_type}"

    if (( pkt_type == DCERPC_PKT_BIND_NAK )); then
        log::error "dcerpc::bind : BIND_NAK — interface refusée par le serveur"
        _dcerpc_ba_dict[result]="${DCERPC_RESULT_REJECT}"
        return 1
    fi

    if (( pkt_type != DCERPC_PKT_BIND_ACK )); then
        log::error "dcerpc::bind : paquet inattendu type=$(printf '%d' ${pkt_type})"
        return 1
    fi

    endian::read_le32 "${pdu}" 12 _dcerpc_ba_dict[call_id]
    endian::read_le16 "${pdu}" 18 _dcerpc_ba_dict[max_recv]

    # Byte 20-23 : SecondaryAddr (variable) — on cherche NumResults
    # SecondaryAddr : LE16 longueur + string null-terminated
    endian::read_le16 "${pdu}" 20 _dcerpc_ba_sec_len
    local -i _sec_len="${_dcerpc_ba_sec_len}"
    # Aligner sur 4 octets : offset après SecondaryAddr
    local -i _sec_end=$(( 22 + _sec_len ))
    local -i _aligned=$(( (_sec_end + 3) & ~3 ))

    # AssocGroupId : 4 octets à _aligned
    endian::read_le32 "${pdu}" "${_aligned}" _dcerpc_ba_dict[assoc_grp]
    local -i _results_off=$(( _aligned + 4 ))

    # NumResults : LE16
    endian::read_le16 "${pdu}" "${_results_off}" _dcerpc_ba_num
    # Result du premier contexte : LE16 à _results_off+2+2 (après NumResults+Align)
    local -i _res_off=$(( _results_off + 4 ))
    endian::read_le16 "${pdu}" "${_res_off}" _dcerpc_ba_dict[result]

    if (( _dcerpc_ba_dict[result] != DCERPC_RESULT_ACCEPT )); then
        log::error "dcerpc::bind : contexte rejeté (result=${_dcerpc_ba_dict[result]})"
        return 1
    fi

    log::debug "dcerpc::bind : ACK call_id=${_dcerpc_ba_dict[call_id]} assoc=${_dcerpc_ba_dict[assoc_grp]} max_recv=${_dcerpc_ba_dict[max_recv]}"
}
