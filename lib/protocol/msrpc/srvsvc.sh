#!/usr/bin/env bash
#
# lib/protocol/msrpc/srvsvc.sh — MSRPC Server Service (SRVSVC)
#
# Permet d'énumérer les partages réseau via le named pipe \srvsvc.
# Implémente NetrShareEnum (OpNum 15) et NetrShareGetInfo (OpNum 16).
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
ensh::import protocol/smb/smb2/header

# ── Constantes SRVSVC ─────────────────────────────────────────────────────────

readonly SRVSVC_OPNUM_NET_SHARE_ENUM=15
readonly SRVSVC_OPNUM_NET_SHARE_GET_INFO=16

readonly SRVSVC_INFO_LEVEL_1=1
readonly SRVSVC_INFO_LEVEL_2=2

readonly SRVSVC_ERR_SUCCESS=0x00000000
readonly SRVSVC_ERR_ACCESS_DENIED=0x00000005
readonly SRVSVC_ERR_INVALID_LEVEL=0x0000007C
readonly SRVSVC_ERR_NOT_SUPPORTED=0x00000032
readonly SRVSVC_ERR_NET_NAME_NOT_FOUND=0x00000906

# Types de partages
readonly SRVSVC_SHARE_TYPE_DISK=0
readonly SRVSVC_SHARE_TYPE_PRINT=1
readonly SRVSVC_SHARE_TYPE_DEVICE=2
readonly SRVSVC_SHARE_TYPE_IPC=3
readonly SRVSVC_SHARE_TYPE_SPECIAL=0x80000000  # bit31 = caché (C$, ADMIN$...)

# ── Helpers NDR32 ─────────────────────────────────────────────────────────────

# ndr::wstr <var_out> <string> [null_terminated_int]
#
# Encode le référent NDR32 d'une chaîne WCHAR* :
#   MaxCount (4B) + Offset (4B) + ActualCount (4B) + UTF-16LE data + padding
_SRVSVC_REF_ID=0x00020000

ndr::wstr() {
    local -n _ndr_wstr_out="$1"
    local str="$2"
    local -i with_nul="${3:-0}"

    local utf16
    utf16::encode_le "${str}" utf16
    local -i char_count=$(( ${#utf16} / 4 ))  # nombre de caractères UTF-16 (2B chacun)

    if (( with_nul != 0 )); then
        utf16+="0000"
        (( char_count++ ))
    fi

    local -i byte_count=$(( ${#utf16} / 2 ))

    local count_le offset_le
    endian::le32 "${char_count}"       count_le
    endian::le32 0                     offset_le

    # Padding pour aligner sur 4 octets
    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    local padding=""
    (( pad > 0 )) && printf -v padding '%0*d' $(( pad * 2 )) 0

    _ndr_wstr_out="${count_le}${offset_le}${count_le}${utf16}${padding}"
}

# ndr::wstr_ptr <var_out>
#
# Encode un pointeur WCHAR* unique (seulement le ReferentId).
ndr::wstr_ptr() {
    local -n _ndr_wsptr_out="$1"
    endian::le32 "${_SRVSVC_REF_ID}" _ndr_wsptr_out
    (( _SRVSVC_REF_ID++ ))
}

# ndr::read_wstr <hex_stub> <offset_bytes> <var_str_out> <var_next_offset_out>
#
# Lit une chaîne NDR32 WCHAR* (MaxCount + Offset + ActualCount + data + padding).
# Retourne la chaîne décodée et l'offset suivant (en octets).
ndr::read_wstr() {
    local stub="${1^^}"
    local -i off="$2"
    local -n _ndr_rw_str="$3"
    local -n _ndr_rw_next="$4"

    # MaxCount (4B)
    endian::read_le32 "${stub}" "${off}" _ndr_rw_max
    (( off += 4 ))
    # Offset (4B)
    (( off += 4 ))
    # ActualCount (4B)
    endian::read_le32 "${stub}" "${off}" _ndr_rw_cnt
    (( off += 4 ))
    local -i char_count="${_ndr_rw_cnt}"
    local -i byte_count=$(( char_count * 2 ))

    # Données UTF-16LE
    local utf16_hex="${stub:$(( off * 2 )):$(( byte_count * 2 ))}"
    (( off += byte_count ))

    # Padding aligné sur 4 octets
    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    (( off += pad ))

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
    local -i mid tid _dfs_h=0
    smb2::_next_msg_id "${_sess}" mid
    tid="${_SMB_TREE_IPC[${_sess}]:-0}"

    smb2::ioctl::build_request ioctl_req \
        "${SMB2_FSCTL_PIPE_TRANSCEIVE}" \
        "${file_id}" \
        "${bind_pdu}" \
        "${mid}" \
        "${_SMB_SESSION_ID[${_sess}]}" \
        "${tid}" \
        "${SMB2_IOCTL_MAX_OUTPUT}" \
        "${_dfs_h}"

    smb::_send "${_sess}" "${ioctl_req}" || return 1

    local resp
    smb::_recv "${_sess}" resp 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${resp}" ioctl_resp || return 1

    local -A ack
    dcerpc::bind::parse_ack "${ioctl_resp[output]}" ack || return 1

    log::info "srvsvc : BIND OK — assoc_grp=${ack[assoc_grp]}"
}

# srvsvc::_build_net_share_enum_stub <server_name> <var_out>
#
# Construit le stub NDR32 de NetrShareEnum niveau 1.
srvsvc::_build_net_share_enum_stub() {
    local server_name="$1"
    local -n _srvsvc_stub_out="$2"

    _SRVSVC_REF_ID=0x00020000

    # ServerName : pointeur référent + données "\\\\server\\0"
    local srv_ptr srv_data
    ndr::wstr_ptr srv_ptr
    ndr::wstr srv_data "\\\\${server_name}" 1

    local level_le ctr_ptr ctr_count_le pref_le resume_le
    endian::le32 1 level_le
    endian::le32 "${_SRVSVC_REF_ID}" ctr_ptr
    (( _SRVSVC_REF_ID++ ))
    endian::le32 0 ctr_count_le
    endian::le32 0xFFFFFFFF pref_le
    endian::le32 0 resume_le

    _srvsvc_stub_out=""
    _srvsvc_stub_out+="${srv_ptr}"
    _srvsvc_stub_out+="${srv_data}"
    _srvsvc_stub_out+="${level_le}"
    _srvsvc_stub_out+="${level_le}"
    _srvsvc_stub_out+="${ctr_ptr}"
    _srvsvc_stub_out+="${ctr_count_le}"
    _srvsvc_stub_out+="00000000"
    _srvsvc_stub_out+="${pref_le}"
    _srvsvc_stub_out+="${resume_le}"
}

# srvsvc::_build_net_share_get_info_stub <server_name> <share_name> <level_int> <var_out>
#
# Construit le stub NDR32 de NetrShareGetInfo.
srvsvc::_build_net_share_get_info_stub() {
    local server_name="$1"
    local share_name="$2"
    local -i level="${3:-${SRVSVC_INFO_LEVEL_2}}"
    local -n _srvsvc_sgi_stub_out="$4"

    _SRVSVC_REF_ID=0x00020000

    local srv_ptr srv_data share_data level_le
    ndr::wstr_ptr srv_ptr
    ndr::wstr srv_data "\\\\${server_name}" 1
    ndr::wstr share_data "${share_name}" 1
    endian::le32 "${level}" level_le

    _srvsvc_sgi_stub_out=""
    _srvsvc_sgi_stub_out+="${srv_ptr}"
    _srvsvc_sgi_stub_out+="${srv_data}"
    _srvsvc_sgi_stub_out+="${share_data}"
    _srvsvc_sgi_stub_out+="${level_le}"
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

    local stub
    srvsvc::_build_net_share_enum_stub "${server_name}" stub

    # ── Envoi via DCE/RPC REQUEST ─────────────────────────────────────────────
    local rpc_req
    dcerpc::request::build rpc_req "${SRVSVC_OPNUM_NET_SHARE_ENUM}" "${stub}" 2

    local ioctl_req
    local -i mid tid _dfs_h=0
    smb2::_next_msg_id "${_sess}" mid
    tid="${_SMB_TREE_IPC[${_sess}]:-0}"

    smb2::ioctl::build_request ioctl_req \
        "${SMB2_FSCTL_PIPE_TRANSCEIVE}" \
        "${file_id}" \
        "${rpc_req}" \
        "${mid}" \
        "${_SMB_SESSION_ID[${_sess}]}" \
        "${tid}" \
        65536 \
        "${_dfs_h}"

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

# srvsvc::net_share_get_info <sess> <file_id_hex32> <server_name> <share_name> <var_dict_out>
#
# Appelle NetrShareGetInfo (OpNum 16). Tente d'abord le niveau 2, puis retombe
# au niveau 1 si le serveur refuse les détails étendus.
srvsvc::net_share_get_info() {
    local _sess="$1"
    local file_id="$2"
    local server_name="$3"
    local share_name="$4"
    local -n _srvsvc_sgi_out="$5"

    local -a try_levels=("${SRVSVC_INFO_LEVEL_2}" "${SRVSVC_INFO_LEVEL_1}")
    local -i level
    for level in "${try_levels[@]}"; do
        local stub
        srvsvc::_build_net_share_get_info_stub "${server_name}" "${share_name}" "${level}" stub

        local rpc_req
        dcerpc::request::build rpc_req "${SRVSVC_OPNUM_NET_SHARE_GET_INFO}" "${stub}" 3

        local ioctl_req
        local -i mid tid _dfs_h=0
        smb2::_next_msg_id "${_sess}" mid
        tid="${_SMB_TREE_IPC[${_sess}]:-0}"

        smb2::ioctl::build_request ioctl_req \
            "${SMB2_FSCTL_PIPE_TRANSCEIVE}" \
            "${file_id}" \
            "${rpc_req}" \
            "${mid}" \
            "${_SMB_SESSION_ID[${_sess}]}" \
            "${tid}" \
            65536 \
            "${_dfs_h}"

        smb::_send "${_sess}" "${ioctl_req}" || return 1

        local resp
        smb::_recv "${_sess}" resp 15 || return 1

        local -A ioctl_resp
        smb2::ioctl::parse_response "${resp}" ioctl_resp || return 1

        local -A rpc_resp
        dcerpc::request::parse_response "${ioctl_resp[output]}" rpc_resp || return 1

        srvsvc::_parse_net_share_get_info_resp "${rpc_resp[stub]}" _srvsvc_sgi_out || return 1

        if (( _srvsvc_sgi_out[error_code] == SRVSVC_ERR_SUCCESS )); then
            log::debug "srvsvc : get_info '${share_name}' niveau=${_srvsvc_sgi_out[level]}"
            return 0
        fi

        if (( level == SRVSVC_INFO_LEVEL_2 )) && \
           (( _srvsvc_sgi_out[error_code] == SRVSVC_ERR_ACCESS_DENIED || \
              _srvsvc_sgi_out[error_code] == SRVSVC_ERR_INVALID_LEVEL || \
              _srvsvc_sgi_out[error_code] == SRVSVC_ERR_NOT_SUPPORTED )); then
            log::debug "srvsvc : get_info '${share_name}' niveau 2 refusé, fallback niveau 1"
            continue
        fi

        log::error "srvsvc : get_info '${share_name}' error=0x$(printf '%08X' "${_srvsvc_sgi_out[error_code]}")"
        return 1
    done

    log::error "srvsvc : get_info '${share_name}' a échoué pour tous les niveaux"
    return 1
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
    (( off += 12 ))

    # Count
    endian::read_le32 "${stub}" "${off}" _srvsvc_count
    (( off += 4 ))
    local -i count="${_srvsvc_count}"

    # Buffer pointer (4B)
    (( off += 4 ))

    # MaxCount (4B) = count
    (( off += 4 ))

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
        (( off += 4 ))

        endian::read_le32 "${stub}" "${off}" _srvsvc_type
        types+=("${_srvsvc_type}")
        (( off += 4 ))

        endian::read_le32 "${stub}" "${off}" _srvsvc_rptr
        remark_ptrs+=("${_srvsvc_rptr}")
        (( off += 4 ))
    done

    # Lire les chaînes déréférencées dans l'ordre de marshaling NDR :
    # pour chaque SHARE_INFO_1, netname puis remark.
    local -a names=()
    local -a remarks=()

    for (( i = 0; i < count; i++ )); do
        if (( name_ptrs[i] != 0 )); then
            local _name _next_off
            ndr::read_wstr "${stub}" "${off}" _name _next_off
            names[i]="${_name}"
            off="${_next_off}"
        else
            names[i]=""
        fi

        if (( remark_ptrs[i] != 0 )); then
            local _remark _next_off2
            ndr::read_wstr "${stub}" "${off}" _remark _next_off2
            remarks[i]="${_remark}"
            off="${_next_off2}"
        else
            remarks[i]=""
        fi
    done

    for (( i = 0; i < count; i++ )); do
        _srvsvc_parse_out+=("${names[i]}:${types[i]}:${remarks[i]}")
    done

    log::debug "srvsvc : ${count} partage(s) reçu(s)"
}

# srvsvc::_parse_net_share_get_info_resp <stub_hex> <var_dict_out>
#
# Parse le stub NDR32 retourné par NetrShareGetInfo niveau 1 ou 2.
srvsvc::_parse_net_share_get_info_resp() {
    local stub="${1^^}"
    local -n _srvsvc_sgi_dict="$2"

    _srvsvc_sgi_dict=()
    _srvsvc_sgi_dict[name]=""
    _srvsvc_sgi_dict[type]="0"
    _srvsvc_sgi_dict[remark]=""
    _srvsvc_sgi_dict[permissions]="0"
    _srvsvc_sgi_dict[max_uses]="0"
    _srvsvc_sgi_dict[current_uses]="0"
    _srvsvc_sgi_dict[path]=""
    _srvsvc_sgi_dict[passwd]=""

    local -i stub_len=$(( ${#stub} / 2 ))
    if (( stub_len < 8 )); then
        log::error "srvsvc : réponse NetrShareGetInfo trop courte"
        return 1
    fi

    endian::read_le32 "${stub}" 0 _srvsvc_sgi_dict[level]
    endian::read_le32 "${stub}" "$(( stub_len - 4 ))" _srvsvc_sgi_dict[error_code]

    local -i info_ptr
    endian::read_le32 "${stub}" 4 info_ptr
    (( info_ptr == 0 )) && return 0

    local -i off=8
    local -i name_ptr remark_ptr path_ptr passwd_ptr

    case "${_srvsvc_sgi_dict[level]}" in
        ${SRVSVC_INFO_LEVEL_1})
            endian::read_le32 "${stub}" "${off}" name_ptr
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" _srvsvc_sgi_dict[type]
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" remark_ptr
            (( off += 4 ))

            if (( name_ptr != 0 )); then
                local _name _next_off
                ndr::read_wstr "${stub}" "${off}" _name _next_off
                _srvsvc_sgi_dict[name]="${_name}"
                off="${_next_off}"
            fi
            if (( remark_ptr != 0 )); then
                local _remark _next_off2
                ndr::read_wstr "${stub}" "${off}" _remark _next_off2
                _srvsvc_sgi_dict[remark]="${_remark}"
                off="${_next_off2}"
            fi
            ;;

        ${SRVSVC_INFO_LEVEL_2})
            endian::read_le32 "${stub}" "${off}" name_ptr
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" _srvsvc_sgi_dict[type]
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" remark_ptr
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" _srvsvc_sgi_dict[permissions]
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" _srvsvc_sgi_dict[max_uses]
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" _srvsvc_sgi_dict[current_uses]
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" path_ptr
            (( off += 4 ))
            endian::read_le32 "${stub}" "${off}" passwd_ptr
            (( off += 4 ))

            if (( name_ptr != 0 )); then
                local _name2 _next_off3
                ndr::read_wstr "${stub}" "${off}" _name2 _next_off3
                _srvsvc_sgi_dict[name]="${_name2}"
                off="${_next_off3}"
            fi
            if (( remark_ptr != 0 )); then
                local _remark2 _next_off4
                ndr::read_wstr "${stub}" "${off}" _remark2 _next_off4
                _srvsvc_sgi_dict[remark]="${_remark2}"
                off="${_next_off4}"
            fi
            if (( path_ptr != 0 )); then
                local _path _next_off5
                ndr::read_wstr "${stub}" "${off}" _path _next_off5
                _srvsvc_sgi_dict[path]="${_path}"
                off="${_next_off5}"
            fi
            if (( passwd_ptr != 0 )); then
                local _passwd _next_off6
                ndr::read_wstr "${stub}" "${off}" _passwd _next_off6
                _srvsvc_sgi_dict[passwd]="${_passwd}"
                off="${_next_off6}"
            fi
            ;;

        *)
            log::error "srvsvc : niveau GetInfo non supporté (${_srvsvc_sgi_dict[level]})"
            return 1
            ;;
    esac
}
