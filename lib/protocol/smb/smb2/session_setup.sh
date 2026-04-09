#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/session_setup.sh — SMB2 SESSION_SETUP (commande 0x0001)
#
# Implémente l'authentification SMB2 via NTLMSSP/SPNEGO.
# Échange identique à SMB1 sur le plan logique, mais avec l'en-tête SMB2.
#
# Requête (StructureSize=25) :
#   [SMB2 header — cmd=0x0001]
#   StructureSize        : LE16 = 25
#   Flags                : 1 octet (0 = SESSION_FLAG_BINDING absent)
#   SecurityMode         : 1 octet (0x01 = SIGNING_ENABLED)
#   Capabilities         : LE32 (capacités client)
#   Channel              : LE32 = 0
#   SecurityBufferOffset : LE16 (offset depuis début msg SMB2)
#   SecurityBufferLength : LE16
#   PreviousSessionId    : LE64 = 0
#   SecurityBuffer       : blob SPNEGO
#
# Réponse (StructureSize=9) :
#   [SMB2 header — SessionId assigné si status=SUCCESS ou MORE_PROCESSING]
#   StructureSize        : LE16 = 9
#   SessionFlags         : LE16 (0=user, 0x0001=guest, 0x0002=encrypt)
#   SecurityBufferOffset : LE16
#   SecurityBufferLength : LE16
#   SecurityBuffer       : blob SPNEGO de réponse
#
# Status de réponse :
#   0x00000000 — SUCCESS (authentification complète)
#   0xC0000016 — MORE_PROCESSING_REQUIRED (en attente de la phase 2)
#   0xC000006D — LOGON_FAILURE (mauvais credentials)
#
# Dépendances : core/endian, core/log, protocol/smb/smb2/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_SESSION_SETUP:-}" ]] && return 0
readonly _ENSH_SMB2_SESSION_SETUP=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb2/header

# ── Construction ──────────────────────────────────────────────────────────────

# _smb2_ss_body <spnego_blob_hex> <var_body_out>
#
# Construit le corps d'un SMB2 SESSION_SETUP.
# Le SecurityBufferOffset = 88 = 64 (header) + 24 (body fixe).
_smb2_ss_body() {
    local spnego="${1^^}"
    local -n _smb2_ss_b_out="$2"

    local -i blob_len=$(( ${#spnego} / 2 ))
    local -i sec_buf_off=88  # 64 (header) + 24 (corps fixe)

    local blob_len_le sec_buf_off_le caps_le
    endian::le16 "${blob_len}"     blob_len_le
    endian::le16 "${sec_buf_off}"  sec_buf_off_le
    endian::le32 "${SMB2_CLIENT_CAPS}" caps_le

    # StructureSize = 25 → LE16 = "1900"
    _smb2_ss_b_out="1900"
    _smb2_ss_b_out+="00"             # Flags = 0
    _smb2_ss_b_out+="01"             # SecurityMode = SIGNING_ENABLED
    _smb2_ss_b_out+="${caps_le}"     # Capabilities
    _smb2_ss_b_out+="00000000"       # Channel = 0
    _smb2_ss_b_out+="${sec_buf_off_le}" # SecurityBufferOffset
    _smb2_ss_b_out+="${blob_len_le}" # SecurityBufferLength
    _smb2_ss_b_out+="0000000000000000" # PreviousSessionId = 0
    _smb2_ss_b_out+="${spnego}"      # SecurityBuffer
}

# smb2::session_setup::build_ntlm_init <var_out> <spnego_blob_hex> <msg_id_int>
#                                      [session_id_hex16]
#
# Premier SMB2 SESSION_SETUP (NTLM Negotiate dans SPNEGO NegTokenInit).
smb2::session_setup::build_ntlm_init() {
    local -n _smb2_ssi_out="$1"
    local spnego="${2^^}"
    local -i msg_id="$3"
    local session_id="${4:-0000000000000000}"

    local hdr body
    # CreditCharge=1 obligatoire pour tout ce qui n'est pas NEGOTIATE (§3.3.5.2.7.1)
    smb2::header::build hdr \
        "${SMB2_CMD_SESSION_SETUP}" "${msg_id}" \
        "${session_id}" 0 0 0 1 1

    _smb2_ss_body "${spnego}" body
    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_ssi_out
    log::debug "smb2::session_setup : NegTokenInit prêt (msg_id=${msg_id})"
}

# smb2::session_setup::build_ntlm_auth <var_out> <spnego_blob_hex>
#                                      <msg_id_int> <session_id_hex16>
#
# Troisième échange SMB2 SESSION_SETUP (NTLM Authenticate dans NegTokenResp).
smb2::session_setup::build_ntlm_auth() {
    local -n _smb2_ssa_out="$1"
    local spnego="${2^^}"
    local -i msg_id="$3"
    local session_id="${4:-0000000000000000}"

    local hdr body
    smb2::header::build hdr \
        "${SMB2_CMD_SESSION_SETUP}" "${msg_id}" \
        "${session_id}" 0 0 0 1 1

    _smb2_ss_body "${spnego}" body
    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_ssa_out
    log::debug "smb2::session_setup : NegTokenResp prêt (msg_id=${msg_id})"
}

# ── Parsing ───────────────────────────────────────────────────────────────────

# smb2::session_setup::parse_response <hex_smb2_msg> <var_dict_out>
#
# Parse un SMB2 SESSION_SETUP Response.
# Remplit le tableau avec :
#   status       — NT Status (décimal)
#   session_id   — SessionId (hex LE64, 16 nibbles)
#   session_flags — flags de session (0=user, 1=guest)
#   spnego_blob  — blob SPNEGO du serveur
smb2::session_setup::parse_response() {
    local msg="${1^^}"
    local -n _smb2_ss_pr_dict="$2"

    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1

    _smb2_ss_pr_dict[status]="${_hdr[status]}"
    _smb2_ss_pr_dict[session_id]="${_hdr[session_id]}"

    # Corps à partir du byte 64
    # StructureSize  : bytes 64-65
    # SessionFlags   : bytes 66-67
    # SecBufOffset   : bytes 68-69
    # SecBufLength   : bytes 70-71
    endian::read_le16 "${msg}" 66 _smb2_ss_pr_dict[session_flags]

    local -i sec_buf_off sec_buf_len
    endian::read_le16 "${msg}" 68 sec_buf_off
    endian::read_le16 "${msg}" 70 sec_buf_len

    if (( sec_buf_len > 0 && sec_buf_off > 0 )); then
        hex::slice "${msg}" "${sec_buf_off}" "${sec_buf_len}" _smb2_ss_pr_dict[spnego_blob]
    else
        _smb2_ss_pr_dict[spnego_blob]=""
    fi

    log::debug "smb2::session_setup : status=0x$(printf '%08X' ${_smb2_ss_pr_dict[status]}) session_id=${_smb2_ss_pr_dict[session_id]}"
}
