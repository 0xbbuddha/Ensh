#!/usr/bin/env bash
#
# lib/protocol/smb/smb1/header.sh — En-tête SMB1 (32 octets fixes)
#
# Structure de l'en-tête SMB1 (MS-SMB §2.2.1) :
#
#   Offset  Taille  Champ
#   ──────  ──────  ─────────────────────────────────────────────────────
#    0       4      Protocol   : 0xFF 'S' 'M' 'B'
#    4       1      Command    : code de la commande
#    5       4      Status     : NT Status (LE32), ou ErrorClass/ErrorCode
#    9       1      Flags      : drapeaux client/serveur
#   10       2      Flags2     : drapeaux étendus (LE16)
#   12       2      PIDHigh    : partie haute du PID (LE16)
#   14       8      Signature  : signature HMAC (0 si non signé)
#   22       2      Reserved   : 0x0000
#   24       2      TID        : Tree Identifier (LE16)
#   26       2      PID        : Process ID partie basse (LE16)
#   28       2      UID        : User Identifier (LE16)
#   30       2      MID        : Multiplex Identifier (LE16)
#
# Après l'en-tête : WordCount (1) | Words (WordCount×2) | ByteCount (2) | Data
#
# Dépendances : core/hex, core/endian, core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB1_HEADER:-}" ]] && return 0
readonly _ENSH_SMB1_HEADER=1

ensh::import core/hex
ensh::import core/endian
ensh::import core/log

# ── Codes de commandes SMB1 ───────────────────────────────────────────────────

readonly SMB1_CMD_CREATE_DIRECTORY=0x00
readonly SMB1_CMD_DELETE=0x06
readonly SMB1_CMD_OPEN=0x02
readonly SMB1_CMD_CLOSE=0x04
readonly SMB1_CMD_ECHO=0x2B
readonly SMB1_CMD_TREE_CONNECT_ANDX=0x75
readonly SMB1_CMD_TREE_DISCONNECT=0x71
readonly SMB1_CMD_NEGOTIATE=0x72
readonly SMB1_CMD_SESSION_SETUP_ANDX=0x73
readonly SMB1_CMD_LOGOFF_ANDX=0x74
readonly SMB1_CMD_NT_CREATE_ANDX=0xA2
readonly SMB1_CMD_TRANS=0x25
readonly SMB1_CMD_TRANS2=0x32
readonly SMB1_CMD_NT_TRANS=0xA0

# ── Drapeaux (Flags, 1 octet) ─────────────────────────────────────────────────

readonly SMB1_FLAGS_LOCK_AND_READ_OK=0x01
readonly SMB1_FLAGS_BUF_AVAIL=0x02
readonly SMB1_FLAGS_CASE_INSENSITIVE=0x08   # noms de fichiers insensibles à la casse
readonly SMB1_FLAGS_CANONICALIZED_PATHS=0x10
readonly SMB1_FLAGS_OPLOCK=0x20
readonly SMB1_FLAGS_OPBATCH=0x40
readonly SMB1_FLAGS_REPLY=0x80              # positionné par le serveur dans les réponses

# ── Drapeaux étendus (Flags2, 2 octets LE) ───────────────────────────────────

readonly SMB1_FLAGS2_LONG_NAMES=0x0001         # noms longs autorisés
readonly SMB1_FLAGS2_EAS=0x0002                # Extended Attributes
readonly SMB1_FLAGS2_SMB_SEC_SIG=0x0004        # signature SMB (optionnelle)
readonly SMB1_FLAGS2_IS_LONG_NAME=0x0040       # chemin contient un nom long
readonly SMB1_FLAGS2_EXT_SEC=0x0800            # Extended Security (SPNEGO)
readonly SMB1_FLAGS2_DFS=0x1000                # support DFS
readonly SMB1_FLAGS2_READ_IF_EXECUTE=0x2000
readonly SMB1_FLAGS2_NT_STATUS=0x4000          # utilise NT Status codes
readonly SMB1_FLAGS2_UNICODE=0x8000            # chaînes en UTF-16LE

# ── Capacités serveur/client (Capabilities, 4 octets LE) ─────────────────────

readonly SMB1_CAP_UNICODE=0x00000001
readonly SMB1_CAP_LARGE_FILES=0x00000002
readonly SMB1_CAP_NT_SMBS=0x00000004
readonly SMB1_CAP_RPC_REMOTE_APIS=0x00000008
readonly SMB1_CAP_STATUS32=0x00000040          # NT Status codes
readonly SMB1_CAP_LEVEL_II_OPLOCKS=0x00000080
readonly SMB1_CAP_LOCK_AND_READ=0x00000100
readonly SMB1_CAP_NT_FIND=0x00000200
readonly SMB1_CAP_LARGE_READX=0x00004000
readonly SMB1_CAP_LARGE_WRITEX=0x00008000
readonly SMB1_CAP_EXTENDED_SECURITY=0x80000000 # SPNEGO

# ── NT Status codes ───────────────────────────────────────────────────────────

readonly SMB1_STATUS_SUCCESS=0x00000000
readonly SMB1_STATUS_MORE_PROCESSING=0xC0000016  # auth en cours (SessionSetup #1)
readonly SMB1_STATUS_LOGON_FAILURE=0xC000006D    # mauvais credentials
readonly SMB1_STATUS_ACCESS_DENIED=0xC0000022
readonly SMB1_STATUS_BAD_NETWORK_NAME=0xC00000CC # share introuvable
readonly SMB1_STATUS_NOT_SUPPORTED=0xC00000BB

# ── Signature protocole ───────────────────────────────────────────────────────

readonly SMB1_PROTO_SIG="FF534D42"  # 0xFF 'S' 'M' 'B'

# ── Drapeaux par défaut du client ─────────────────────────────────────────────

readonly SMB1_DEFAULT_FLAGS=0x18     # CASE_INSENSITIVE | CANONICALIZED_PATHS
# Flags2 : UNICODE | NT_STATUS | EXT_SEC | LONG_NAMES
readonly SMB1_DEFAULT_FLAGS2=0xC801

# ── Construction de l'en-tête ────────────────────────────────────────────────

# smb1::header::build <var_out> <cmd_int> <tid_int> <pid_int> <uid_int> <mid_int>
#                     [flags_int] [flags2_int] [status_int]
#
# Construit un en-tête SMB1 de 32 octets.
# Tous les entiers sont en notation décimale ou hexadécimale (0x...).
smb1::header::build() {
    local -n _smb1_hb_out="$1"
    local -i cmd="$2"
    local -i tid="$3"
    local -i pid="$4"
    local -i uid="$5"
    local -i mid="$6"
    local -i flags="${7:-${SMB1_DEFAULT_FLAGS}}"
    local -i flags2="${8:-${SMB1_DEFAULT_FLAGS2}}"
    local -i status="${9:-0}"

    local cmd_hex flags_hex flags2_le tid_le pid_le uid_le mid_le status_le

    printf -v cmd_hex    '%02X' "${cmd}"
    printf -v flags_hex  '%02X' "${flags}"
    endian::le16 "${flags2}" flags2_le
    endian::le16 "${tid}"    tid_le
    endian::le16 "${pid}"    pid_le
    endian::le16 "${uid}"    uid_le
    endian::le16 "${mid}"    mid_le
    endian::le32 "${status}" status_le

    # En-tête complet :
    # [Sig 4][Cmd 1][Status 4][Flags 1][Flags2 2][PIDHigh 2][Signature 8][Reserved 2][TID 2][PID 2][UID 2][MID 2]
    _smb1_hb_out="${SMB1_PROTO_SIG}"
    _smb1_hb_out+="${cmd_hex}"
    _smb1_hb_out+="${status_le}"
    _smb1_hb_out+="${flags_hex}"
    _smb1_hb_out+="${flags2_le}"
    _smb1_hb_out+="0000"                   # PIDHigh
    _smb1_hb_out+="0000000000000000"       # Signature (non signé)
    _smb1_hb_out+="0000"                   # Reserved
    _smb1_hb_out+="${tid_le}"
    _smb1_hb_out+="${pid_le}"
    _smb1_hb_out+="${uid_le}"
    _smb1_hb_out+="${mid_le}"
}

# ── Parsing de l'en-tête ──────────────────────────────────────────────────────

# smb1::header::parse <hex_msg> <var_dict_out>
#
# Parse les 32 premiers octets d'un message SMB1.
# Remplit un tableau associatif avec :
#   protocol, cmd, status, flags, flags2, tid, pid, uid, mid
# Retourne 1 si la signature est invalide.
smb1::header::parse() {
    local msg="${1^^}"
    local -n _smb1_hp_dict="$2"

    # Vérification de la signature
    if [[ "${msg:0:8}" != "${SMB1_PROTO_SIG}" ]]; then
        log::error "smb1::header::parse : signature invalide (${msg:0:8})"
        return 1
    fi

    _smb1_hp_dict[cmd]="$(( 16#${msg:8:2} ))"
    endian::read_le32 "${msg}" 5 _smb1_hp_dict[status]
    _smb1_hp_dict[flags]="$(( 16#${msg:18:2} ))"
    endian::read_le16 "${msg}" 10 _smb1_hp_dict[flags2]
    endian::read_le16 "${msg}" 24 _smb1_hp_dict[tid]
    endian::read_le16 "${msg}" 26 _smb1_hp_dict[pid]
    endian::read_le16 "${msg}" 28 _smb1_hp_dict[uid]
    endian::read_le16 "${msg}" 30 _smb1_hp_dict[mid]
}

# ── Framing NBT (Session Message) ─────────────────────────────────────────────

# smb1::nbt_wrap <smb_hex> <var_out>
#
# Encapsule un message SMB dans un header NBT Session Message (4 octets).
# Format : 0x00 | 0x00 | Length(BE16)
# Utilisé sur port 445 (Direct TCP) comme sur port 139.
smb1::nbt_wrap() {
    local smb="${1^^}"
    local -n _smb1_nw_out="$2"
    local -i plen=$(( ${#smb} / 2 ))
    local len_be
    endian::be16 "${plen}" len_be
    _smb1_nw_out="0000${len_be}${smb}"
}

# smb1::nbt_unwrap <nbt_msg_hex> <var_smb_out>
#
# Retire le header NBT et retourne le payload SMB.
smb1::nbt_unwrap() {
    local msg="${1^^}"
    local -n _smb1_nu_out="$2"
    # Skip 4-byte NBT header (8 nibbles)
    _smb1_nu_out="${msg:8}"
}
