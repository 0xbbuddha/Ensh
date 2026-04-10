#!/usr/bin/env bash
#
# lib/protocol/msrpc/srvsvc.sh — MSRPC Server Service (SRVSVC)
#
# Permet d'énumérer les partages réseau via le named pipe \srvsvc.
# Implémente NetrShareEnum (OpNum 15) niveau 1 (nom + type + commentaire).
#
# Flux d'utilisation :
#   1. smb::session::open_pipe sess "\srvsvc" file_id
#   2. srvsvc::bind sess file_id
#   3. srvsvc::net_share_enum sess file_id server_name shares_out
#   4. smb::session::close_pipe sess file_id
#
# NDR32 : encodage little-endian, pointeurs conformants, tableaux conformants.
# Un pointeur NDR32 non-nul = référent unique 32 bits (0x00020000, 0x00020004...).
#
# Structure NetrShareEnum Request (Level 1) :
#   ServerName    : [unique] WCHAR* (pointeur + longueur + données UTF-16LE)
#   InfoStruct    : LPSHARE_ENUM_STRUCT
#     Level       : DWORD = 1
#     ShareInfo   : [switch_is(Level)] union SHARE_ENUM_UNION
#       Level1    : LPSHARE_INFO_1_CONTAINER
#         Ctr     : [unique] SHARE_INFO_1_CONTAINER*
#           Count : DWORD
#           Buffer: [unique][size_is(Count)] LPSHARE_INFO_1
#   PrefMaxLen    : DWORD = 0xFFFFFFFF (illimité)
#   ResumeHandle  : [unique] DWORD* → NULL = 0x00000000
#
# Structure SHARE_INFO_1 :
#   shi1_netname  : [unique] WCHAR* — nom du partage
#   shi1_type     : DWORD — type (0=disk, 1=print, 2=device, 3=IPC, bit31=special)
#   shi1_remark   : [unique] WCHAR* — commentaire
#
# Dépendances : core/endian, core/log, encoding/utf16, protocol/dcerpc/bind,
#               protocol/dcerpc/request
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_MSRPC_SRVSVC:-}" ]] && return 0
readonly _ENSH_MSRPC_SRVSVC=1

ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/dcerpc/bind
ensh::import protocol/dcerpc/request

# ── Constantes SRVSVC ─────────────────────────────────────────────────────────

readonly SRVSVC_OPNUM_NET_SHARE_ENUM=15

# Types de partages
readonly SRVSVC_SHARE_TYPE_DISK=0
readonly SRVSVC_SHARE_TYPE_PRINT=1
readonly SRVSVC_SHARE_TYPE_DEVICE=2
readonly SRVSVC_SHARE_TYPE_IPC=3
readonly SRVSVC_SHARE_TYPE_SPECIAL=0x80000000  # bit31 = caché (C$, ADMIN$...)

# ── Helpers NDR32 ─────────────────────────────────────────────────────────────

# ndr::wstr <var_out> <string>
#
# Encode une chaîne en NDR32 WCHAR* unique pointer :
#   ReferentId (4B) + MaxCount (4B) + Offset (4B) + ActualCount (4B) + UTF-16LE data + padding
# Le ReferentId est un compteur croissant simulé (0x00020000).
_SRVSVC_REF_ID=0x00020000

ndr::wstr() {
    local -n _ndr_wstr_out="$1"
    local str="$2"

    local utf16
    utf16::encode_le "${str}" utf16
    local -i char_count=$(( ${#utf16} / 4 ))  # nombre de caractères UTF-16 (2B chacun)
    local -i byte_count=$(( ${#utf16} / 2 ))

    local ref_le count_le offset_le
    endian::le32 "${_SRVSVC_REF_ID}"  ref_le
    endian::le32 "${char_count}"       count_le
    endian::le32 0                     offset_le

    # Padding pour aligner sur 4 octets
    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    local padding
    printf -v padding '%0*d' $(( pad * 2 )) 0

    _ndr_wstr_out="${ref_le}${count_le}${offset_le}${count_le}${utf16}${padding}"
    (( _SRVSVC_REF_ID++ ))
}

# ndr::wstr_ptr <var_out> <string>
#
# Encode un pointeur WCHAR* unique (seulement le ReferentId).
# Les données réelles doivent être ajoutées séparément après tous les pointeurs.
ndr::wstr_ptr() {
    local -n _ndr_wsptr_out="$1"
    endian::le32 "${_SRVSVC_REF_ID}" _ndr_wsptr_out
    (( _SRVSVC_REF_ID++ ))
}

# ndr::read_wstr <hex_stub> <offset_nibbles> <var_str_out> <var_next_offset_out>
#
# Lit une chaîne NDR32 WCHAR* (MaxCount + Offset + ActualCount + data + padding).
# Retourne la chaîne décodée et l'offset suivant (en nibbles).
ndr::read_wstr() {
    local stub="${1^^}"
    local -i off="$2"
    local -n _ndr_rw_str="$3"
    local -n _ndr_rw_next="$4"

    # MaxCount (4B)
    endian::read_le32 "${stub}" "${off}" _ndr_rw_max
    (( off += 8 ))  # +4 octets
    # Offset (4B)
    (( off += 8 ))  # +4 octets (ignoré)
    # ActualCount (4B)
    endian::read_le32 "${stub}" "${off}" _ndr_rw_cnt
    (( off += 8 ))
    local -i char_count="${_ndr_rw_cnt}"
    local -i byte_count=$(( char_count * 2 ))
    local -i nibble_count=$(( byte_count * 2 ))

    # Données UTF-16LE
    local utf16_hex="${stub:${off}:${nibble_count}}"
    (( off += nibble_count ))

    # Padding aligné sur 4 octets
    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    (( off += pad * 2 ))

    # Décoder UTF-16LE → ASCII/UTF-8
    utf16::decode_le "${utf16_hex}" _ndr_rw_str
    _ndr_rw_next="${off}"
}

# ── BIND SRVSVC ───────────────────────────────────────────────────────────────

# srvsvc::bind <sess> <file_id_hex32>
#
# Effectue un DCE/RPC BIND sur l'interface SRVSVC via le pipe déjà ouvert.
srvsvc::bind() {
    local _sess="$1"
    local file_id="$2"

    local bind_pdu
    dcerpc::bind::build bind_pdu \
        "${DCERPC_IF_SRVSVC_UUID}" \
        "${DCERPC_IF_SRVSVC_VER_MAJ}" \
        "${DCERPC_IF_SRVSVC_VER_MIN}" \
        1

    local ioctl_req
    local -i mid tid
    smb2::_next_msg_id "${_sess}" mid
    tid="${_SMB_TREE_IPC[${_sess}]:-0}"

    smb2::ioctl::build_request ioctl_req \
        "${SMB2_FSCTL_PIPE_TRANSCEIVE}" \
        "${file_id}" \
        "${bind_pdu}" \
        "${mid}" \
        "${_SMB_SESSION_ID[${_sess}]}" \
        "${tid}"

    smb::_send "${_sess}" "${ioctl_req}" || return 1

    local resp
    smb::_recv "${_sess}" resp 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${resp}" ioctl_resp || return 1

    local -A ack
    dcerpc::bind::parse_ack "${ioctl_resp[output]}" ack || return 1

    log::info "srvsvc : BIND OK — assoc_grp=${ack[assoc_grp]}"
}

# ── NetrShareEnum ─────────────────────────────────────────────────────────────

# srvsvc::net_share_enum <sess> <file_id_hex32> <server_name> <var_list_out>
#
# Appelle NetrShareEnum (OpNum 15, Level 1) et retourne la liste des partages.
# <var_list_out> : tableau indexé rempli avec des entrées "NOM:TYPE:COMMENTAIRE"
srvsvc::net_share_enum() {
    local _sess="$1"
    local file_id="$2"
    local server_name="$3"
    local -n _srvsvc_nse_out="$4"

    _SRVSVC_REF_ID=0x00020000

    # ── Construction du stub NDR32 ────────────────────────────────────────────
    #
    # NetrShareEnum(
    #   ServerName   : [unique] WCHAR* → \\server
    #   InfoStruct   : SHARE_ENUM_STRUCT { Level=1, ShareInfo={Ctr=NULL} }
    #   PrefMaxLen   : DWORD = 0xFFFFFFFF
    #   ResumeHandle : [unique] DWORD* → NULL
    # )

    # ServerName : pointeur référent + données
    local srv_ptr srv_data
    ndr::wstr_ptr srv_ptr
    ndr::wstr srv_data "\\\\${server_name}"

    # Level = 1
    local level_le
    endian::le32 1 level_le

    # Switch value (= Level, répété dans l'union)
    # Ctr (LPSHARE_INFO_1_CONTAINER) : pointeur non-nul
    local ctr_ptr
    endian::le32 "${_SRVSVC_REF_ID}" ctr_ptr
    (( _SRVSVC_REF_ID++ ))

    # SHARE_INFO_1_CONTAINER : Count=0, Buffer=NULL (le serveur les remplira)
    local ctr_count_le
    endian::le32 0 ctr_count_le

    # PrefMaxLen = 0xFFFFFFFF
    local pref_le
    endian::le32 0xFFFFFFFF pref_le

    # ResumeHandle : pointeur NULL
    local resume_le
    endian::le32 0 resume_le

    local stub=""
    stub+="${srv_ptr}"      # ServerName pointer
    stub+="${level_le}"     # Level = 1
    stub+="${level_le}"     # Switch value = 1
    stub+="${ctr_ptr}"      # Ctr pointer
    stub+="${ctr_count_le}" # Count = 0
    stub+="00000000"        # Buffer pointer = NULL
    stub+="${srv_data}"     # ServerName data (déréférencement)
    stub+="${pref_le}"      # PrefMaxLen
    stub+="${resume_le}"    # ResumeHandle = NULL

    # ── Envoi via DCE/RPC REQUEST ─────────────────────────────────────────────
    local rpc_req
    dcerpc::request::build rpc_req "${SRVSVC_OPNUM_NET_SHARE_ENUM}" "${stub}" 2

    local ioctl_req
    local -i mid tid
    smb2::_next_msg_id "${_sess}" mid
    tid="${_SMB_TREE_IPC[${_sess}]:-0}"

    smb2::ioctl::build_request ioctl_req \
        "${SMB2_FSCTL_PIPE_TRANSCEIVE}" \
        "${file_id}" \
        "${rpc_req}" \
        "${mid}" \
        "${_SMB_SESSION_ID[${_sess}]}" \
        "${tid}" \
        65536

    smb::_send "${_sess}" "${ioctl_req}" || return 1

    local resp
    smb::_recv "${_sess}" resp 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${resp}" ioctl_resp || return 1

    local -A rpc_resp
    dcerpc::request::parse_response "${ioctl_resp[output]}" rpc_resp || return 1

    # ── Parsing du stub de réponse ────────────────────────────────────────────
    srvsvc::_parse_net_share_enum_resp "${rpc_resp[stub]}" _srvsvc_nse_out
}

# srvsvc::_parse_net_share_enum_resp <stub_hex> <var_list_out>
#
# Parse le stub NDR32 retourné par NetrShareEnum Level 1.
# Rempli <var_list_out> avec : "NOM:TYPE:COMMENTAIRE"
srvsvc::_parse_net_share_enum_resp() {
    local stub="${1^^}"
    local -n _srvsvc_parse_out="$2"
    _srvsvc_parse_out=()

    # Le stub de réponse NetrShareEnum Level 1 :
    # [0]   Level          : LE32 = 1
    # [4]   Switch value   : LE32 = 1
    # [8]   Ctr pointer    : LE32 (non-nul)
    # [12]  Count          : LE32 — nombre d'entrées
    # [16]  Buffer pointer : LE32 (non-nul)
    # [20]  MaxCount       : LE32 (identique à Count)
    # [24+] SHARE_INFO_1[] : tableau d'entrées
    #         shi1_netname ptr : LE32
    #         shi1_type        : LE32
    #         shi1_remark ptr  : LE32
    # puis déréférencement des chaînes dans l'ordre des pointeurs

    local -i off=0

    # Level (4B) + Switch (4B) + Ctr ptr (4B)
    (( off += 24 ))  # 3 * 4 octets * 2 nibbles = 24 nibbles

    # Count
    endian::read_le32 "${stub}" "${off}" _srvsvc_count
    (( off += 8 ))
    local -i count="${_srvsvc_count}"

    # Buffer pointer (4B)
    (( off += 8 ))

    # MaxCount (4B) = count
    (( off += 8 ))

    if (( count == 0 )); then
        log::warn "srvsvc : aucun partage retourné"
        return 0
    fi

    # Lire les 'count' entrées SHARE_INFO_1 (chacune : 3 * LE32 = 12 octets = 24 nibbles)
    local -a name_ptrs=()
    local -a types=()
    local -a remark_ptrs=()

    local -i i
    for (( i = 0; i < count; i++ )); do
        endian::read_le32 "${stub}" "${off}" _srvsvc_nptr
        name_ptrs+=("${_srvsvc_nptr}")
        (( off += 8 ))

        endian::read_le32 "${stub}" "${off}" _srvsvc_type
        types+=("${_srvsvc_type}")
        (( off += 8 ))

        endian::read_le32 "${stub}" "${off}" _srvsvc_rptr
        remark_ptrs+=("${_srvsvc_rptr}")
        (( off += 8 ))
    done

    # Lire les chaînes déréférencées (dans l'ordre des pointeurs non-nuls)
    local -a names=()
    local -a remarks=()

    for (( i = 0; i < count; i++ )); do
        if (( name_ptrs[i] != 0 )); then
            local _name _next_off
            ndr::read_wstr "${stub}" "${off}" _name _next_off
            names+=("${_name}")
            off="${_next_off}"
        else
            names+=("")
        fi
    done

    for (( i = 0; i < count; i++ )); do
        if (( remark_ptrs[i] != 0 )); then
            local _remark _next_off2
            ndr::read_wstr "${stub}" "${off}" _remark _next_off2
            remarks+=("${_remark}")
            off="${_next_off2}"
        else
            remarks+=("")
        fi
    done

    for (( i = 0; i < count; i++ )); do
        _srvsvc_parse_out+=("${names[i]}:${types[i]}:${remarks[i]}")
    done

    log::debug "srvsvc : ${count} partage(s) reçu(s)"
}
