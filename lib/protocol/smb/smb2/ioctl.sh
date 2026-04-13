#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/ioctl.sh — SMB2 IOCTL (commande 0x000B)
#
# Permet d'envoyer des commandes de contrôle sur des fichiers/pipes ouverts.
# Usage principal : FSCTL_PIPE_TRANSCEIVE pour le transport DCE/RPC sur IPC$.
#
# Requête (StructureSize=57) :
#   [SMB2 header]
#   StructureSize : LE16 = 57
#   Reserved      : LE16 = 0
#   CtlCode       : LE32 — code FSCTL
#   FileId        : 16 octets (Persistent 8B + Volatile 8B)
#   InputOffset   : LE32 — offset données input depuis début msg SMB2
#   InputCount    : LE32 — taille données input
#   MaxInputResp  : LE32 — taille max réponse input (0 pour PIPE_TRANSCEIVE)
#   OutputOffset  : LE32 — offset données output (0 dans la requête)
#   OutputCount   : LE32 — 0 dans la requête
#   MaxOutputResp : LE32 — taille max réponse output
#   Flags         : LE32 — 0x00000001 = FSCTL (vs IOCTL)
#   [données input]
#
# Réponse (StructureSize=49) :
#   [SMB2 header]
#   StructureSize : LE16 = 49
#   Reserved      : LE16 = 0
#   CtlCode       : LE32
#   FileId        : 16 octets
#   InputOffset   : LE32
#   InputCount    : LE32
#   OutputOffset  : LE32
#   OutputCount   : LE32
#   Flags         : LE32
#   Reserved2     : LE32
#   [données output]
#
# Dépendances : core/endian, core/log, protocol/smb/smb2/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_IOCTL:-}" ]] && return 0
readonly _ENSH_SMB2_IOCTL=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb2/header

# ── Codes FSCTL ───────────────────────────────────────────────────────────────

# FSCTL_PIPE_TRANSCEIVE : envoie + reçoit en un seul aller-retour sur un pipe.
# C'est le transport DCE/RPC pour les named pipes (SRVSVC, SAMR, LSARPC...).
readonly SMB2_FSCTL_PIPE_TRANSCEIVE=0x0011C017

# FSCTL_PIPE_WAIT : attend qu'une instance de pipe soit disponible.
readonly SMB2_FSCTL_PIPE_WAIT=0x00110018

# FSCTL_DFS_GET_REFERRALS : requête DFS (Distributed File System).
readonly SMB2_FSCTL_DFS_GET_REFERRALS=0x00060194

# Flags IOCTL
readonly SMB2_IOCTL_FLAG_IS_FSCTL=0x00000001

# Taille max de réponse par défaut pour PIPE_TRANSCEIVE (4096 octets)
readonly SMB2_IOCTL_MAX_OUTPUT=4096

# ── Construction ──────────────────────────────────────────────────────────────

# smb2::ioctl::build_request <var_out> <ctl_code_int> <file_id_hex32>
#                             <input_hex> <msg_id_int> <session_id_hex16>
#                             <tree_id_int> [max_output_int] [header_flags_int]
#
# Construit un SMB2 IOCTL complet avec données input.
# <file_id_hex32> : 32 nibbles hex = FileId Persistent(8B) + Volatile(8B)
# <input_hex>     : données à envoyer (stub DCE/RPC, etc.)
smb2::ioctl::build_request() {
    local -n _smb2_io_req_out="$1"
    local -i ctl_code="$2"
    local file_id="${3^^}"
    local input_hex="${4^^}"
    local -i msg_id="$5"
    local session_id="${6:-0000000000000000}"
    local -i tree_id="${7:-0}"
    local -i max_output="${8:-${SMB2_IOCTL_MAX_OUTPUT}}"
    local -i hdr_flags="${9:-0}"

    # ── En-tête SMB2 ─────────────────────────────────────────────────────────
    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_IOCTL}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 "${hdr_flags}" "${SMB2_CREDIT_REQUEST_LARGE}" 1

    # ── Corps IOCTL ───────────────────────────────────────────────────────────
    # InputOffset = 64 (header) + 56 (corps fixe sans input) = 120
    local -i input_len=$(( ${#input_hex} / 2 ))
    local -i input_off=120
    local -i max_input=0   # 0 pour PIPE_TRANSCEIVE

    local ctl_le input_off_le input_len_le max_in_le max_out_le flags_le
    endian::le32 "${ctl_code}"   ctl_le
    endian::le32 "${input_off}"  input_off_le
    endian::le32 "${input_len}"  input_len_le
    endian::le32 "${max_input}"  max_in_le
    endian::le32 0               _smb2_io_dummy_le  # OutputOffset = 0
    endian::le32 0               _smb2_io_dummy2_le # OutputCount  = 0
    endian::le32 "${max_output}" max_out_le
    endian::le32 "${SMB2_IOCTL_FLAG_IS_FSCTL}" flags_le

    local body="3900"                 # StructureSize = 57
    body+="0000"                      # Reserved
    body+="${ctl_le}"                 # CtlCode
    body+="${file_id}"                # FileId (16 octets = 32 nibbles)
    body+="${input_off_le}"           # InputOffset
    body+="${input_len_le}"           # InputCount
    body+="${max_in_le}"              # MaxInputResponse
    body+="00000000"                  # OutputOffset = 0
    body+="00000000"                  # OutputCount  = 0
    body+="${max_out_le}"             # MaxOutputResponse
    body+="${flags_le}"               # Flags
    body+="00000000"                  # Reserved2
    body+="${input_hex}"              # données input

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_io_req_out
    log::debug "smb2::ioctl : ctl=0x$(printf '%08X' ${ctl_code}) input=${input_len}B"
}

# ── Parsing ───────────────────────────────────────────────────────────────────

# smb2::ioctl::parse_response <hex_smb2_msg> <var_dict_out>
#
# Parse un SMB2 IOCTL Response.
# Remplit le tableau avec :
#   status      — NT Status
#   ctl_code    — CtlCode retourné
#   output      — données output en hex (payload DCE/RPC)
#   output_len  — taille en octets
smb2::ioctl::parse_response() {
    local msg="${1^^}"
    local -n _smb2_io_pr_dict="$2"

    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1

    _smb2_io_pr_dict[status]="${_hdr[status]}"

    if (( _hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::debug "smb2::ioctl : status=0x$(printf '%08X' ${_hdr[status]})"
        return 1
    fi

    # Corps à partir du byte 64 (128 nibbles)
    # [64-65] StructureSize
    # [66-67] Reserved
    # [68-71] CtlCode
    # [72-87] FileId (16 octets)
    # [88-91] InputOffset
    # [92-95] InputCount
    # [96-99] OutputOffset
    # [100-103] OutputCount
    # [104-107] Flags
    # [108-111] Reserved2

    endian::read_le32 "${msg}" 68  _smb2_io_pr_dict[ctl_code]
    endian::read_le32 "${msg}" 96  _smb2_io_out_off
    endian::read_le32 "${msg}" 100 _smb2_io_pr_dict[output_len]

    local -i _out_off="${_smb2_io_out_off}"
    local -i _out_len="${_smb2_io_pr_dict[output_len]}"

    if (( _out_len > 0 )); then
        hex::slice "${msg}" "${_out_off}" "${_out_len}" _smb2_io_pr_dict[output]
    else
        _smb2_io_pr_dict[output]=""
    fi

    log::debug "smb2::ioctl : output=${_out_len}B ctl=0x$(printf '%08X' ${_smb2_io_pr_dict[ctl_code]})"
}
