#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/negotiate.sh — SMB2 NEGOTIATE (commande 0x0000)
#
# Le NEGOTIATE SMB2 permet au client de sélectionner un dialecte et d'obtenir
# les capacités du serveur ainsi que son blob SPNEGO.
#
# Requête (StructureSize=36) :
#   [SMB2 header — cmd=0x0000, MessageId=0, SessionId=0, TreeId=0]
#   StructureSize      : LE16 = 36
#   DialectCount       : LE16
#   SecurityMode       : LE16 (0x0001 = SIGNING_ENABLED)
#   Reserved           : LE16 = 0
#   Capabilities       : LE32
#   ClientGuid         : 16 octets (GUID aléatoire du client)
#   ClientStartTime    : LE64 = 0 (ou NegotiateContextOffset pour 3.1.1)
#   Dialects           : DialectCount × LE16
#
# Réponse (StructureSize=65) :
#   [SMB2 header]
#   StructureSize          : LE16 = 65
#   SecurityMode           : LE16
#   DialectRevision        : LE16 — dialecte choisi par le serveur
#   NegotiateContextCount  : LE16 (0 pour < 3.1.1)
#   ServerGuid             : 16 octets
#   Capabilities           : LE32
#   MaxTransactSize        : LE32
#   MaxReadSize            : LE32
#   MaxWriteSize           : LE32
#   SystemTime             : LE64 (FILETIME)
#   ServerStartTime        : LE64
#   SecurityBufferOffset   : LE16 (offset depuis début du message SMB2)
#   SecurityBufferLength   : LE16
#   NegotiateContextOffset : LE32 (0 pour < 3.1.1)
#   SecurityBuffer         : SPNEGO NegTokenInit du serveur
#
# Dépendances : core/endian, core/log, protocol/smb/smb2/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_NEGOTIATE:-}" ]] && return 0
readonly _ENSH_SMB2_NEGOTIATE=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb2/header

# ── Capacités client par défaut ───────────────────────────────────────────────

# DFS + LARGE_MTU : suffisant pour les opérations de base
readonly SMB2_CLIENT_CAPS=$(( SMB2_CAP_DFS | SMB2_CAP_LARGE_MTU ))

# ── Construction de la requête ────────────────────────────────────────────────

# smb2::negotiate::build_request <var_out> [msg_id]
#
# Construit un SMB2 NEGOTIATE complet avec framing NBT.
# Par défaut : dialectes 2.0.2 et 2.1 seulement (signature HMAC-SHA256, pas AES-CMAC 3.x) —
# meilleure interop avec les piles qui négocient 3.x tout en restant sensibles aux détails
# de longueur / compound sur les réponses signées.
# Pour proposer aussi 3.0 / 3.0.2 : ENSH_SMB_NEGOTIATE_SMB3=1
smb2::negotiate::build_request() {
    local -n _smb2_neg_req_out="$1"
    local -i msg_id="${2:-0}"

    # ── En-tête SMB2 ─────────────────────────────────────────────────────────
    # CreditCharge=0 obligatoire pour NEGOTIATE (MS-SMB2 §2.2.3)
    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_NEGOTIATE}" "${msg_id}" \
        "0000000000000000" 0 0 0 1 0

    # ── Dialectes ─────────────────────────────────────────────────────────────
    local _d dialects=""
    local -a _dialect_list=( "${SMB2_DIALECT_202}" "${SMB2_DIALECT_210}" )
    if [[ "${ENSH_SMB_NEGOTIATE_SMB3:-}" == "1" ]]; then
        _dialect_list+=( "${SMB2_DIALECT_300}" "${SMB2_DIALECT_302}" )
    fi
    for _d in "${_dialect_list[@]}"; do
        local _d_le; endian::le16 "${_d}" _d_le
        dialects+="${_d_le}"
    done
    local -i dialect_count="${#_dialect_list[@]}"

    # ── Corps fixe ────────────────────────────────────────────────────────────
    local dc_le sec_le caps_le
    endian::le16 "${dialect_count}"  dc_le
    endian::le16 "${SMB2_SEC_SIGNING_ENABLED}" sec_le
    endian::le32 "${SMB2_CLIENT_CAPS}" caps_le

    # ClientGuid : 16 octets pseudo-aléatoires
    local client_guid
    printf -v client_guid '%04X%04X%04X%04X%04X%04X%04X%04X' \
        "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}" \
        "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}"

    # StructureSize=36 en LE16 = "2400"
    local body="2400"
    body+="${dc_le}"           # DialectCount
    body+="${sec_le}"          # SecurityMode
    body+="0000"               # Reserved
    body+="${caps_le}"         # Capabilities
    body+="${client_guid}"     # ClientGuid (16 octets)
    body+="0000000000000000"   # ClientStartTime = 0
    body+="${dialects}"        # Dialects

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_neg_req_out
    log::debug "smb2::negotiate : requête (${dialect_count} dialectes)"
}

# ── Parsing de la réponse ─────────────────────────────────────────────────────

# smb2::negotiate::parse_response <hex_smb2_msg> <var_dict_out>
#
# Parse un SMB2 NEGOTIATE Response (message SMB2 sans framing NBT).
# Remplit le tableau avec :
#   status           — NT Status
#   dialect          — dialecte choisi (décimal)
#   capabilities     — capacités serveur (décimal)
#   security_mode    — mode de sécurité
#   max_transact     — MaxTransactSize
#   max_read         — MaxReadSize
#   max_write        — MaxWriteSize
#   server_guid      — GUID serveur (hex 16 octets)
#   spnego_blob      — blob SPNEGO du serveur (hex)
smb2::negotiate::parse_response() {
    local msg="${1^^}"
    local -n _smb2_neg_resp_dict="$2"

    # ── En-tête ────────────────────────────────────────────────────────────
    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1
    _smb2_neg_resp_dict[status]="${_hdr[status]}"

    if (( _hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb2::negotiate : status=0x$(printf '%08X' ${_hdr[status]})"
        return 1
    fi

    # ── Corps (à partir du byte 64) ───────────────────────────────────────
    # StructureSize   : bytes 64-65
    # SecurityMode    : bytes 66-67
    # DialectRevision : bytes 68-69
    # (NC Count)      : bytes 70-71
    # ServerGuid      : bytes 72-87
    # Capabilities    : bytes 88-91
    # MaxTransactSize : bytes 92-95
    # MaxReadSize     : bytes 96-99
    # MaxWriteSize    : bytes 100-103
    # SystemTime      : bytes 104-111
    # ServerStartTime : bytes 112-119
    # SecBufOffset    : bytes 120-121
    # SecBufLength    : bytes 122-123
    # NCOffset        : bytes 124-127
    # SecurityBuffer  : à SecBufOffset depuis début du message SMB2

    endian::read_le16 "${msg}" 66  _smb2_neg_resp_dict[security_mode]
    endian::read_le16 "${msg}" 68  _smb2_neg_resp_dict[dialect]
    hex::slice "${msg}" 72 16      _smb2_neg_resp_dict[server_guid]
    endian::read_le32 "${msg}" 88  _smb2_neg_resp_dict[capabilities]
    endian::read_le32 "${msg}" 92  _smb2_neg_resp_dict[max_transact]
    endian::read_le32 "${msg}" 96  _smb2_neg_resp_dict[max_read]
    endian::read_le32 "${msg}" 100 _smb2_neg_resp_dict[max_write]
    hex::slice "${msg}" 104 8      _smb2_neg_resp_dict[system_time]

    local -i sec_buf_off sec_buf_len
    endian::read_le16 "${msg}" 120 sec_buf_off
    endian::read_le16 "${msg}" 122 sec_buf_len

    if (( sec_buf_len > 0 && sec_buf_off > 0 )); then
        hex::slice "${msg}" "${sec_buf_off}" "${sec_buf_len}" _smb2_neg_resp_dict[spnego_blob]
    else
        _smb2_neg_resp_dict[spnego_blob]=""
    fi

    log::debug "smb2::negotiate : dialecte=0x$(printf '%04X' ${_smb2_neg_resp_dict[dialect]}) caps=0x$(printf '%08X' ${_smb2_neg_resp_dict[capabilities]})"
}
