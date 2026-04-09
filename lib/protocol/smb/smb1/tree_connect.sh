#!/usr/bin/env bash
#
# lib/protocol/smb/smb1/tree_connect.sh — SMB_COM_TREE_CONNECT_ANDX (0x75)
#
# TreeConnect permet au client de se connecter à un partage réseau (IPC$, C$, etc.).
# Le TID (Tree Identifier) retourné doit être utilisé dans toutes les commandes
# suivantes sur ce partage.
#
# Requête (WordCount=4) :
#   [SMB header]
#   WC=4
#   AndXCommand     : 0xFF
#   AndXReserved    : 0x00
#   AndXOffset      : 0x0000
#   Flags           : LE16 — TREE_CONNECT_ANDX_DISCONNECT_TID(0x0001) ou 0
#   PasswordLength  : LE16 — 1 (null password pour mode extended security)
#   ByteCount       : LE16 = PasswordLength + Path + Service
#   Password        : 0x00 (1 octet, null)
#   Path            : UNC en Unicode null-terminated (ex: \\SERVER\IPC$)
#   Service         : ASCII null-terminated (ex: "?????" = any, "IPC" = IPC$)
#
# Réponse (WordCount=3 ou 7) :
#   [SMB header] — TID contient l'ID du partage (si status=SUCCESS)
#   WC=3 ou 7
#   AndXCommand, AndXReserved, AndXOffset
#   OptionalSupport : LE16
#   (+ MaximalShareAccessRights, GuestMaximalShareAccessRights si WC=7)
#   ByteCount
#   ServiceType     : ASCII (ex: "IPC\x00", "A:\x00")
#   ExtraParameters : variable
#
# Dépendances : core/endian, core/log, encoding/utf16, protocol/smb/smb1/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB1_TREE_CONNECT:-}" ]] && return 0
readonly _ENSH_SMB1_TREE_CONNECT=1

ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/smb/smb1/header

# ── Construction de la requête ────────────────────────────────────────────────

# smb1::tree_connect::build_request <var_out> <uid_int> <unc_path> <mid_int>
#                                   [pid] [service]
#
# Construit un SMB_COM_TREE_CONNECT_ANDX complet.
# <unc_path> : chemin UNC ex: "\\10.10.10.1\IPC$"
# <service>  : "?????" (any), "IPC" (IPC$), "A:" (disk share)
smb1::tree_connect::build_request() {
    local -n _smb1_tc_req_out="$1"
    local -i uid="$2"
    local unc_path="$3"
    local -i mid="$4"
    local -i pid="${5:-1234}"
    local service="${6:-?????}"

    # ── En-tête SMB ──────────────────────────────────────────────────────────
    # TID=0 (pas encore connecté à un partage)
    local hdr
    smb1::header::build hdr \
        "${SMB1_CMD_TREE_CONNECT_ANDX}" \
        0 "${pid}" "${uid}" "${mid}" \
        "${SMB1_DEFAULT_FLAGS}" "${SMB1_DEFAULT_FLAGS2}"

    # ── Encodage du chemin en UTF-16LE + null terminator ─────────────────────
    # Remplacer les \ par des \ (déjà OK) et encoder
    local path_utf16
    utf16::encode_le "${unc_path}" path_utf16
    path_utf16+="0000"  # null terminator UTF-16LE

    # Service en ASCII + null
    local service_hex
    hex::from_string "${service}" service_hex
    service_hex+="00"

    # Password = 0x00 (1 octet) pour mode extended security
    local password="00"
    local -i pwd_len=1

    local -i path_len=$(( ${#path_utf16} / 2 ))
    local -i svc_len=$(( ${#service_hex} / 2 ))
    local -i bc=$(( pwd_len + path_len + svc_len ))

    local pwd_len_le bc_le
    endian::le16 "${pwd_len}" pwd_len_le
    endian::le16 "${bc}"      bc_le

    # ── Words (4 mots = 8 octets) ────────────────────────────────────────────
    local words=""
    words+="FF"           # AndXCommand = 0xFF
    words+="00"           # AndXReserved
    words+="0000"         # AndXOffset
    words+="0000"         # Flags = 0
    words+="${pwd_len_le}" # PasswordLength

    local wc="04"
    local data="${password}${path_utf16}${service_hex}"
    local smb="${hdr}${wc}${words}${bc_le}${data}"

    smb1::nbt_wrap "${smb}" _smb1_tc_req_out
    log::debug "smb1::tree_connect : requête pour '${unc_path}' (uid=${uid})"
}

# ── Parsing de la réponse ─────────────────────────────────────────────────────

# smb1::tree_connect::parse_response <hex_msg> <var_dict_out>
#
# Parse une réponse SMB_COM_TREE_CONNECT_ANDX.
# Remplit le tableau associatif avec :
#   status        — NT Status (décimal)
#   tid           — Tree ID attribué (depuis l'en-tête SMB)
#   service_type  — type de service (ex: "IPC", "A:")
# Retourne 1 si status != SUCCESS.
smb1::tree_connect::parse_response() {
    local msg="${1^^}"
    local -n _smb1_tc_pr_dict="$2"

    # ── En-tête ────────────────────────────────────────────────────────────
    local -A _hdr
    smb1::header::parse "${msg}" _hdr || return 1

    _smb1_tc_pr_dict[status]="${_hdr[status]}"
    _smb1_tc_pr_dict[tid]="${_hdr[tid]}"

    if (( _hdr[status] != SMB1_STATUS_SUCCESS )); then
        log::debug "smb1::tree_connect : erreur status=0x$(printf '%08X' ${_hdr[status]})"
        return 1
    fi

    # ── WordCount (byte 32) ────────────────────────────────────────────────
    local -i wc=$(( 16#${msg:64:2} ))

    # ── ByteCount ──────────────────────────────────────────────────────────
    # Selon wc : byte 33 + wc*2 + (1 pour wc byte lui-même)
    local -i bc_off=$(( 33 + wc * 2 ))
    local -i bc
    endian::read_le16 "${msg}" "${bc_off}" bc

    # ── ServiceType (ASCII après ByteCount) ────────────────────────────────
    local -i data_off=$(( bc_off + 2 ))
    if (( bc > 0 )); then
        # Lire jusqu'au null
        local svc_hex=""
        local -i i
        for (( i = 0; i < bc; i++ )); do
            local byte
            hex::slice "${msg}" "$(( data_off + i ))" 1 byte
            [[ "${byte}" == "00" ]] && break
            svc_hex+="${byte}"
        done
        hex::to_string "${svc_hex}" _smb1_tc_pr_dict[service_type]
    else
        _smb1_tc_pr_dict[service_type]=""
    fi

    log::debug "smb1::tree_connect : tid=${_smb1_tc_pr_dict[tid]} service='${_smb1_tc_pr_dict[service_type]}'"
}
