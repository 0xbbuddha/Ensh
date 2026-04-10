#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/tree_connect.sh — SMB2 TREE_CONNECT (commande 0x0003)
#
# Permet de se connecter à un partage SMB2. Le TreeId retourné dans l'en-tête
# de la réponse doit être inclus dans toutes les commandes suivantes sur ce partage.
#
# Requête (StructureSize=9) :
#   [SMB2 header]
#   StructureSize : LE16 = 9
#   Reserved      : LE16 = 0   (ou Flags pour 3.1.1)
#   PathOffset    : LE16 (offset du Path depuis début du message SMB2 = 72)
#   PathLength    : LE16 (en octets, PAS null-terminated)
#   Path          : UTF-16LE UNC sans null terminator (ex: \\10.10.10.1\IPC$)
#
# Réponse (StructureSize=16) :
#   [SMB2 header — TreeId dans le champ correspondant]
#   StructureSize    : LE16 = 16
#   ShareType        : 1 octet (1=disk, 2=pipe, 3=print)
#   Reserved         : 1 octet
#   ShareFlags       : LE32
#   Capabilities     : LE32
#   MaximalAccess    : LE32
#
# Le TreeId attribué est dans le champ TreeId de l'en-tête SMB2 de la réponse.
#
# Dépendances : core/endian, core/log, encoding/utf16, protocol/smb/smb2/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_TREE_CONNECT:-}" ]] && return 0
readonly _ENSH_SMB2_TREE_CONNECT=1

ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/smb/smb2/header

# Types de partage
readonly SMB2_SHARE_TYPE_DISK=1
readonly SMB2_SHARE_TYPE_PIPE=2
readonly SMB2_SHARE_TYPE_PRINT=3

# ── Construction ──────────────────────────────────────────────────────────────

# smb2::tree_connect::build_request <var_out> <unc_path> <msg_id_int>
#                                   <session_id_hex16>
#
# Construit un SMB2 TREE_CONNECT complet.
# <unc_path> : chemin UNC ex: "\\10.10.10.1\IPC$"
smb2::tree_connect::build_request() {
    local -n _smb2_tc_req_out="$1"
    local unc_path="$2"
    local -i msg_id="$3"
    local session_id="${4:-0000000000000000}"

    # ── En-tête SMB2 ─────────────────────────────────────────────────────────
    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_TREE_CONNECT}" "${msg_id}" \
        "${session_id}" 0 0 0 1 1

    # ── Chemin UNC en UTF-16LE (sans null terminator) ─────────────────────────
    local path_utf16
    utf16::encode_le "${unc_path}" path_utf16
    local -i path_len=$(( ${#path_utf16} / 2 ))

    # PathOffset = 64 (header) + 8 (corps fixe) = 72
    local -i path_off=72
    local path_off_le path_len_le
    endian::le16 "${path_off}" path_off_le
    endian::le16 "${path_len}" path_len_le

    # StructureSize = 9 → "0900" (LE16)
    local body="0900"
    body+="0000"           # Reserved
    body+="${path_off_le}" # PathOffset
    body+="${path_len_le}" # PathLength
    body+="${path_utf16}"  # Path

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_tc_req_out
    log::debug "smb2::tree_connect : '${unc_path}' (msg_id=${msg_id})"
}

# ── Parsing ───────────────────────────────────────────────────────────────────

# smb2::tree_connect::parse_response <hex_smb2_msg> <var_dict_out>
#
# Parse un SMB2 TREE_CONNECT Response.
# Remplit le tableau avec :
#   status     — NT Status
#   tree_id    — Tree ID (depuis l'en-tête SMB2)
#   share_type — type de partage (1=disk, 2=pipe, 3=print)
smb2::tree_connect::parse_response() {
    local msg="${1^^}"
    local -n _smb2_tc_pr_dict="$2"

    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1

    _smb2_tc_pr_dict[status]="${_hdr[status]}"
    _smb2_tc_pr_dict[tree_id]="${_hdr[tree_id]}"

    if (( _hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb2::tree_connect : status=0x$(printf '%08X' ${_hdr[status]})"
        return 1
    fi

    # Corps à partir du byte 64
    # StructureSize  : bytes 64-65
    # ShareType      : byte 66
    # Reserved       : byte 67
    # ShareFlags     : bytes 68-71
    # Capabilities   : bytes 72-75
    # MaximalAccess  : bytes 76-79
    _smb2_tc_pr_dict[share_type]="$(( 16#${msg:132:2} ))"  # byte 66

    log::debug "smb2::tree_connect : tid=${_smb2_tc_pr_dict[tree_id]} type=${_smb2_tc_pr_dict[share_type]}"
}

# smb2::tree_disconnect::build_request <var_out> <msg_id_int>
#                                      <session_id_hex16> <tree_id_int>
#
# Construit un SMB2 TREE_DISCONNECT.
smb2::tree_disconnect::build_request() {
    local -n _smb2_td_out="$1"
    local -i msg_id="$2"
    local session_id="$3"
    local -i tree_id="$4"

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_TREE_DISCONNECT}" "${msg_id}" \
        "${session_id}" "${tree_id}" 0 0 1 1

    # StructureSize = 4, Reserved = 0
    local body="0400" body+="0000"

    local smb="${hdr}${body}"
    smb2::nbt_wrap "${smb}" _smb2_td_out
}
