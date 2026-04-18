#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/header.sh — En-tête SMB2 (64 octets fixes)
#
# Structure de l'en-tête SMB2 (MS-SMB2 §2.2.1.1) :
#
#   Offset  Taille  Champ
#   ──────  ──────  ──────────────────────────────────────────────────────────
#    0       4      ProtocolId    : 0xFE 'S' 'M' 'B'
#    4       2      StructureSize : 64  (taille fixe de l'en-tête)
#    6       2      CreditCharge  : nombre de crédits consommés
#    8       4      Status        : NT Status code (LE32)
#   12       2      Command       : code de la commande SMB2 (LE16)
#   14       2      CreditRequest : crédits demandés/accordés (LE16)
#   16       4      Flags         : drapeaux (LE32)
#   20       4      NextCommand   : offset du prochain cmd (compound, sinon 0)
#   24       8      MessageId     : identifiant de message (LE64)
#   32       4      ProcessId     : ID processus (ou AsyncId lo pour async)
#   36       4      TreeId        : identifiant de partage (LE32)
#   40       8      SessionId     : identifiant de session (LE64)
#   48      16      Signature     : 16 octets (HMAC SMB 2.x ou CMAC SMB 3.x — voir smb2/signing, smb3/signing)
#
# Après l'en-tête : corps de la commande (StructureSize variable selon cmd)
#
# Dépendances : core/hex, core/endian, core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_HEADER:-}" ]] && return 0
readonly _ENSH_SMB2_HEADER=1

ensh::import core/hex
ensh::import core/endian
ensh::import core/log

# ── Codes de commandes SMB2 ───────────────────────────────────────────────────

readonly SMB2_CMD_NEGOTIATE=0x0000
readonly SMB2_CMD_SESSION_SETUP=0x0001
readonly SMB2_CMD_LOGOFF=0x0002
readonly SMB2_CMD_TREE_CONNECT=0x0003
readonly SMB2_CMD_TREE_DISCONNECT=0x0004
readonly SMB2_CMD_CREATE=0x0005
readonly SMB2_CMD_CLOSE=0x0006
readonly SMB2_CMD_FLUSH=0x0007
readonly SMB2_CMD_READ=0x0008
readonly SMB2_CMD_WRITE=0x0009
readonly SMB2_CMD_IOCTL=0x000B
readonly SMB2_CMD_ECHO=0x000D
readonly SMB2_CMD_QUERY_DIRECTORY=0x000E
readonly SMB2_CMD_CHANGE_NOTIFY=0x000F
readonly SMB2_CMD_QUERY_INFO=0x0010
readonly SMB2_CMD_SET_INFO=0x0011

# ── Drapeaux (Flags, 4 octets LE) ────────────────────────────────────────────

readonly SMB2_FLAGS_SERVER_TO_REDIR=0x00000001   # positionné dans les réponses
readonly SMB2_FLAGS_ASYNC_COMMAND=0x00000002
readonly SMB2_FLAGS_RELATED_OPERATIONS=0x00000004
readonly SMB2_FLAGS_SIGNED=0x00000008
readonly SMB2_FLAGS_DFS_OPERATIONS=0x10000000
readonly SMB2_FLAGS_REPLAY_OPERATION=0x20000000

# ── Capacités (Capabilities, 4 octets LE) ────────────────────────────────────

readonly SMB2_CAP_DFS=0x00000001
readonly SMB2_CAP_LEASING=0x00000002
readonly SMB2_CAP_LARGE_MTU=0x00000004
readonly SMB2_CAP_MULTI_CHANNEL=0x00000008
readonly SMB2_CAP_PERSISTENT_HANDLES=0x00000010
readonly SMB2_CAP_DIRECTORY_LEASING=0x00000020
readonly SMB2_CAP_ENCRYPTION=0x00000040

# ── Mode de sécurité ──────────────────────────────────────────────────────────

readonly SMB2_SEC_SIGNING_ENABLED=0x0001    # signature optionnelle
readonly SMB2_SEC_SIGNING_REQUIRED=0x0002   # signature obligatoire

# ── NT Status codes (partagés avec smb1/header.sh) ───────────────────────────

readonly SMB2_STATUS_SUCCESS=0x00000000
readonly SMB2_STATUS_MORE_PROCESSING=0xC0000016
readonly SMB2_STATUS_END_OF_FILE=0xC0000011
readonly SMB2_STATUS_LOGON_FAILURE=0xC000006D
readonly SMB2_STATUS_WRONG_PASSWORD=0xC000006A
readonly SMB2_STATUS_ACCESS_DENIED=0xC0000022
readonly SMB2_STATUS_OBJECT_NAME_NOT_FOUND=0xC0000034
readonly SMB2_STATUS_OBJECT_PATH_NOT_FOUND=0xC000003A
readonly SMB2_STATUS_BAD_NETWORK_NAME=0xC00000CC   # share inexistant
readonly SMB2_STATUS_FILE_IS_A_DIRECTORY=0xC00000BA
readonly SMB2_STATUS_NOT_SUPPORTED=0xC00000BB
readonly SMB2_STATUS_NETWORK_ACCESS_DENIED=0xC00000CA
readonly SMB2_STATUS_BUFFER_OVERFLOW=0x80000005
readonly SMB2_STATUS_NO_MORE_FILES=0x80000006

# ── Dialectes SMB2 ───────────────────────────────────────────────────────────

readonly SMB2_DIALECT_202=0x0202    # SMB 2.0.2 — Windows Vista/2008
readonly SMB2_DIALECT_210=0x0210    # SMB 2.1   — Windows 7/2008R2
readonly SMB2_DIALECT_300=0x0300    # SMB 3.0   — Windows 8/2012
readonly SMB2_DIALECT_302=0x0302    # SMB 3.0.2 — Windows 8.1/2012R2
# Note: 0x0311 (SMB 3.1.1) nécessite NegotiateContexts — pas implémenté ici.

# ── Constantes ───────────────────────────────────────────────────────────────

readonly SMB2_PROTO_SIG="FE534D42"  # 0xFE 'S' 'M' 'B'
readonly SMB2_HEADER_SIZE=64

# Crédits : SESSION_SETUP / première phase → 1 ; après negotiate, clients usuels demandent 127 (impacket sendSMB).
readonly SMB2_CREDIT_REQUEST_SESSION=1
readonly SMB2_CREDIT_REQUEST_LARGE=127

# ── Construction de l'en-tête ─────────────────────────────────────────────────

# smb2::header::build <var_out> <cmd_int> <msg_id_int> <session_id_hex16>
#                     <tree_id_int> [status_int] [flags_int] [credit_int]
#                     [credit_charge_int]
#
# Construit un en-tête SMB2 de 64 octets.
# <session_id_hex16>  : SessionId sous forme de 16 nibbles hex LE
#                       (tel que reçu du serveur, ou "0000000000000000" avant login)
# [credit_charge_int] : CreditCharge (défaut 1). DOIT être 0 pour NEGOTIATE,
#                       DOIT être ≥ 1 pour toutes les autres commandes si le serveur
#                       supporte LARGE_MTU (SMB2_GLOBAL_CAP_LARGE_MTU §3.3.5.2.7.1).
smb2::header::build() {
    local -n _smb2_hb_out="$1"
    local -i cmd="$2"
    local -i msg_id="$3"
    local session_id_hex="${4:-0000000000000000}"
    local -i tree_id="${5:-0}"
    local -i status="${6:-0}"
    local -i flags="${7:-0}"
    local -i credit="${8:-1}"
    local -i credit_charge="${9:-1}"

    local cmd_le status_le flags_le tree_id_le credit_le credit_charge_le msg_id_le

    endian::le16 "${cmd}"            cmd_le
    endian::le32 "${status}"         status_le
    endian::le32 "${flags}"          flags_le
    endian::le32 "${tree_id}"        tree_id_le
    endian::le16 "${credit}"         credit_le
    endian::le16 "${credit_charge}"  credit_charge_le

    # MessageId : 8 octets LE (hi=0 pour MessageId < 2^32)
    local -i _msg_lo=$(( msg_id & 0x7FFFFFFF ))
    endian::le64 0 "${_msg_lo}" msg_id_le

    _smb2_hb_out="${SMB2_PROTO_SIG}"       # [0-3]  ProtocolId
    _smb2_hb_out+="4000"                   # [4-5]  StructureSize = 64
    _smb2_hb_out+="${credit_charge_le}"    # [6-7]  CreditCharge
    _smb2_hb_out+="${status_le}"           # [8-11] Status
    _smb2_hb_out+="${cmd_le}"              # [12-13] Command
    _smb2_hb_out+="${credit_le}"           # [14-15] CreditRequest
    _smb2_hb_out+="${flags_le}"            # [16-19] Flags
    _smb2_hb_out+="00000000"               # [20-23] NextCommand = 0
    _smb2_hb_out+="${msg_id_le}"           # [24-31] MessageId
    _smb2_hb_out+="00000000"               # [32-35] ProcessId = 0
    _smb2_hb_out+="${tree_id_le}"          # [36-39] TreeId
    _smb2_hb_out+="${session_id_hex}"      # [40-47] SessionId (16 nibbles LE)
    _smb2_hb_out+="$(printf '%032d' 0)"    # [48-63] Signature = 0 (16 octets)
}

# ── Parsing de l'en-tête ──────────────────────────────────────────────────────

# smb2::header::parse <hex_smb2_msg> <var_dict_out>
#
# Parse les 64 premiers octets d'un message SMB2.
# Remplit un tableau associatif avec :
#   cmd, status, flags, msg_id, tree_id, session_id (hex), credit
# Retourne 1 si la signature est invalide.
smb2::header::parse() {
    local msg="${1^^}"
    local -n _smb2_hp_dict="$2"

    if [[ "${msg:0:8}" != "${SMB2_PROTO_SIG}" ]]; then
        log::error "smb2::header::parse : signature invalide (${msg:0:8})"
        return 1
    fi

    endian::read_le16 "${msg}" 12 _smb2_hp_dict[cmd]
    endian::read_le32 "${msg}" 8  _smb2_hp_dict[status]
    endian::read_le32 "${msg}" 16 _smb2_hp_dict[flags]
    endian::read_le32 "${msg}" 36 _smb2_hp_dict[tree_id]
    endian::read_le16 "${msg}" 14 _smb2_hp_dict[credit]

    # SessionId : 8 octets à l'offset 40 — stocké en hex brut (LE, tel que reçu)
    hex::slice "${msg}" 40 8 _smb2_hp_dict[session_id]

    # MessageId : 8 octets à l'offset 24 — on lit seulement les 4 premiers (suffisant)
    endian::read_le32 "${msg}" 24 _smb2_hp_dict[msg_id]
}

# ── Framing NBT (identique à SMB1) ───────────────────────────────────────────

# smb2::nbt_wrap <smb2_hex> <var_out>
smb2::nbt_wrap() {
    local smb="${1^^}"
    local -n _smb2_nw_out="$2"
    local -i plen=$(( ${#smb} / 2 ))
    # NetBIOS session message : 0x00 | (length>>16) | length_low (BE16) — aligné impacket / MS-SMB2
    local -i hi=$(( plen >> 16 ))
    local -i lo=$(( plen & 0xFFFF ))
    local lo_be
    endian::be16 "${lo}" lo_be
    printf -v _smb2_nw_out '00%02X%s%s' "$(( hi & 0xFF ))" "${lo_be}" "${smb}"
}
