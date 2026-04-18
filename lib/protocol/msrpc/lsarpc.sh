#!/usr/bin/env bash
#
# lib/protocol/msrpc/lsarpc.sh -- MSRPC Local Security Authority Remote (LSARPC)
#
# Fournit un sous-ensemble utile de MS-LSAD / MS-LSAT sur le named pipe \lsarpc:
#   - LsarClose (OpNum 0)                   -- ferme un handle policy
#   - LsarEnumeratePrivileges (OpNum 2)     -- liste des privilèges LSA
#   - LsarLookupSids (OpNum 15)             -- résolution SID -> nom
#   - LsarOpenPolicy2 (OpNum 44)            -- ouverture d'un handle policy
#   - LsarQueryInformationPolicy2 (OpNum 46)-- infos policy
#
# Flux d'utilisation :
#   1. smb::session::open_pipe sess "\lsarpc" file_id
#   2. lsarpc::bind sess file_id
#   3. lsarpc::open_policy sess file_id policy_handle
#   4. lsarpc::query_info_policy sess file_id policy_handle 12 info
#   5. lsarpc::lookup_sids sess file_id policy_handle sid_list names_out
#   6. lsarpc::enum_privileges sess file_id policy_handle privs_out
#   7. lsarpc::close_handle sess file_id policy_handle
#   8. smb::session::close_pipe sess file_id
#
# Références : MS-LSAD, MS-LSAT
#

[[ -n "${_ENSH_MSRPC_LSARPC:-}" ]] && return 0
readonly _ENSH_MSRPC_LSARPC=1

ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/dcerpc/bind
ensh::import protocol/dcerpc/request
ensh::import protocol/smb/smb2/header

# -- Constantes LSARPC --------------------------------------------------------

readonly LSARPC_OPNUM_CLOSE=0
readonly LSARPC_OPNUM_ENUM_PRIVILEGES=2
readonly LSARPC_OPNUM_LOOKUP_SIDS=15
readonly LSARPC_OPNUM_OPEN_POLICY2=44
readonly LSARPC_OPNUM_QUERY_INFO_POLICY2=46

readonly LSARPC_ACCESS_MAXIMUM_ALLOWED=0x02000000
readonly LSARPC_PREF_MAX_LENGTH=0xFFFFFFFF
readonly LSARPC_LOOKUP_LEVEL_WKSTA=1
readonly LSARPC_POLICY_INFO_AUDIT_EVENTS=2
readonly LSARPC_POLICY_INFO_DOMAIN_DNS=12

readonly LSARPC_STATUS_MORE_ENTRIES=0x00000105
readonly LSARPC_STATUS_SOME_NOT_MAPPED=0x00000107
readonly LSARPC_STATUS_NONE_MAPPED=0xC0000073

readonly LSARPC_HANDLE_SIZE=20

_LSARPC_REF_ID=0x00020000
_LSARPC_CALL_ID=1

# -- Helpers NDR32 ------------------------------------------------------------

_lsarpc_next_ref() {
    local -n _lnr_out="$1"
    endian::le32 "${_LSARPC_REF_ID}" _lnr_out
    (( _LSARPC_REF_ID++ ))
}

_lsarpc_next_call_id() {
    local -n _lnc_out="$1"
    _lnc_out="${_LSARPC_CALL_ID}"
    (( _LSARPC_CALL_ID++ ))
}

_lsarpc_encode_sid() {
    local -n _les_out="$1"
    local sid_hex="${2^^}"

    local -i sub_count=$(( 16#${sid_hex:2:2} ))
    local count_le
    endian::le32 "${sub_count}" count_le

    _les_out="${count_le}${sid_hex}"
}

_lsarpc_decode_sid() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lds_out="$3"
    local -n _lds_next="$4"

    local -i sub_count
    endian::read_le32 "${stub}" "${__ls_off}" sub_count
    (( __ls_off += 4 ))

    local -i sid_bytes=$(( 8 + sub_count * 4 ))
    _lds_out="${stub:$(( __ls_off * 2 )):$(( sid_bytes * 2 ))}"
    (( __ls_off += sid_bytes ))

    _lds_next="${__ls_off}"
}

_lsarpc_read_ustr() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lru_out="$3"
    local -n _lru_next="$4"

    local -i _max_count _actual_count
    endian::read_le32 "${stub}" "${__ls_off}" _max_count
    (( __ls_off += 4 ))
    (( __ls_off += 4 ))
    endian::read_le32 "${stub}" "${__ls_off}" _actual_count
    (( __ls_off += 4 ))

    local -i byte_count=$(( _actual_count * 2 ))
    local utf16_hex="${stub:$(( __ls_off * 2 )):$(( byte_count * 2 ))}"
    (( __ls_off += byte_count ))

    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    (( __ls_off += pad ))

    utf16::decode_le "${utf16_hex}" _lru_out
    _lru_next="${__ls_off}"
}

_lsarpc_read_ustr_inline() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lrui_len="$3"
    local -n _lrui_ptr="$4"
    local -n _lrui_next="$5"

    endian::read_le16 "${stub}" "${__ls_off}" _lrui_len
    (( __ls_off += 2 ))
    (( __ls_off += 2 ))
    endian::read_le32 "${stub}" "${__ls_off}" _lrui_ptr
    (( __ls_off += 4 ))

    _lrui_next="${__ls_off}"
}

_lsarpc_u32_to_s32() {
    local -i value="$1"
    local -n _lu32s_out="$2"

    if (( value >= 0x80000000 )); then
        _lu32s_out=$(( value - 0x100000000 ))
    else
        _lu32s_out="${value}"
    fi
}

_lsarpc_sid_use_name() {
    local -i use="$1"
    local -n _lsun_out="$2"

    case "${use}" in
        1) _lsun_out="user" ;;
        2) _lsun_out="group" ;;
        3) _lsun_out="domain" ;;
        4) _lsun_out="alias" ;;
        5) _lsun_out="well_known_group" ;;
        6) _lsun_out="deleted_account" ;;
        7) _lsun_out="invalid" ;;
        8) _lsun_out="unknown" ;;
        9) _lsun_out="computer" ;;
        10) _lsun_out="label" ;;
        *) _lsun_out="unknown" ;;
    esac
}

_lsarpc_guid_to_str() {
    local guid_hex="${1^^}"
    local -n _lgts_out="$2"

    local -i data1 data2 data3
    endian::read_le32 "${guid_hex}" 0 data1
    endian::read_le16 "${guid_hex}" 4 data2
    endian::read_le16 "${guid_hex}" 6 data3

    _lgts_out="$(printf '%08X-%04X-%04X-%s-%s' \
        "${data1}" \
        "${data2}" \
        "${data3}" \
        "${guid_hex:16:4}" \
        "${guid_hex:20:12}")"
}

# lsarpc::sid::append_rid <sid_hex> <rid_int> <var_out>
#
# Ajoute un RID à un SID brut déjà décodé (sans MaxCount NDR).
lsarpc::sid::append_rid() {
    local base_sid_hex="${1^^}"
    local -i rid="$2"
    local out_var="$3"

    local -i sub_count=$(( 16#${base_sid_hex:2:2} ))
    local new_count rid_le
    printf -v new_count '%02X' $(( (sub_count + 1) & 0xFF ))
    endian::le32 "${rid}" rid_le

    printf -v "${out_var}" '%s' "${base_sid_hex:0:2}${new_count}${base_sid_hex:4}${rid_le}"
}

# -- Builders -----------------------------------------------------------------

_lsarpc_build_open_policy_stub() {
    local -i desired_access="${1:-${LSARPC_ACCESS_MAXIMUM_ALLOWED}}"
    local -n _lbops_out="$2"

    local access_le
    endian::le32 "${desired_access}" access_le

    # SystemName = NULL
    # LSAPR_OBJECT_ATTRIBUTES = 6 DWORDs / pointers NULL
    _lbops_out="00000000"
    _lbops_out+="000000000000000000000000000000000000000000000000"
    _lbops_out+="${access_le}"
}

_lsarpc_build_query_info_policy_stub() {
    local policy_handle="${1^^}"
    local -i info_class="$2"
    local -n _lbqip_out="$3"

    local info_class_le
    endian::le16 "${info_class}" info_class_le

    _lbqip_out="${policy_handle}${info_class_le}"
}

_lsarpc_build_enum_privileges_stub() {
    local policy_handle="${1^^}"
    local -i enum_context="${2:-0}"
    local -i pref_max_len="${3:-0xFFFFFFFF}"
    local -n _lbep_out="$4"

    local enum_le pref_le
    endian::le32 "${enum_context}" enum_le
    endian::le32 "${pref_max_len}" pref_le

    _lbep_out="${policy_handle}${enum_le}${pref_le}"
}

_lsarpc_build_lookup_sids_stub() {
    local policy_handle="${1^^}"
    local -n _lbls_sids="$2"
    local -n _lbls_out="$3"

    _LSARPC_REF_ID=0x00020000

    local -i count="${#_lbls_sids[@]}"
    local count_le sid_array_ptr lookup_level_le names_ptr
    endian::le32 "${count}" count_le
    endian::le16 "${LSARPC_LOOKUP_LEVEL_WKSTA}" lookup_level_le

    if (( count > 0 )); then
        _lsarpc_next_ref sid_array_ptr
    else
        sid_array_ptr="00000000"
    fi

    _lbls_out="${policy_handle}${count_le}${sid_array_ptr}"

    if (( count > 0 )); then
        local -a sid_ptrs=()
        local sid ref sid_enc

        _lbls_out+="${count_le}"
        for sid in "${_lbls_sids[@]}"; do
            _lsarpc_next_ref ref
            sid_ptrs+=("${ref}")
            _lbls_out+="${ref}"
        done

        for sid in "${_lbls_sids[@]}"; do
            _lsarpc_encode_sid sid_enc "${sid}"
            _lbls_out+="${sid_enc}"
        done
    fi

    # LSAPR_TRANSLATED_NAMES initial : pointeur non-nul vers un tableau vide.
    _lsarpc_next_ref names_ptr
    _lbls_out+="00000000${names_ptr}00000000"
    _lbls_out+="${lookup_level_le}0000"
    _lbls_out+="00000000"
}

# -- Parsers ------------------------------------------------------------------

_lsarpc_parse_policy_dns_info() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lppdi_out="$3"
    local -n _lppdi_next="$4"

    local -a str_ptrs=()
    local _len _ptr
    local -i _next_off

    _lsarpc_read_ustr_inline "${stub}" "${__ls_off}" _len _ptr _next_off
    __ls_off="${_next_off}"
    str_ptrs+=("${_ptr}")
    _lsarpc_read_ustr_inline "${stub}" "${__ls_off}" _len _ptr _next_off
    __ls_off="${_next_off}"
    str_ptrs+=("${_ptr}")
    _lsarpc_read_ustr_inline "${stub}" "${__ls_off}" _len _ptr _next_off
    __ls_off="${_next_off}"
    str_ptrs+=("${_ptr}")

    local guid_hex="${stub:$(( __ls_off * 2 )):32}"
    (( __ls_off += 16 ))

    local -i sid_ptr
    endian::read_le32 "${stub}" "${__ls_off}" sid_ptr
    (( __ls_off += 4 ))

    local -a strings=("" "" "")
    local -i i
    for (( i = 0; i < 3; i++ )); do
        if (( str_ptrs[i] != 0 )); then
            local _value _next
            _lsarpc_read_ustr "${stub}" "${__ls_off}" _value _next
            strings[i]="${_value}"
            __ls_off="${_next}"
        fi
    done

    local sid_hex=""
    if (( sid_ptr != 0 )); then
        local _next
        _lsarpc_decode_sid "${stub}" "${__ls_off}" sid_hex _next
        __ls_off="${_next}"
    fi

    local guid_str
    _lsarpc_guid_to_str "${guid_hex}" guid_str

    _lppdi_out[name]="${strings[0]}"
    _lppdi_out[dns_domain]="${strings[1]}"
    _lppdi_out[dns_forest]="${strings[2]}"
    _lppdi_out[domain_guid]="${guid_str}"
    _lppdi_out[domain_sid]="${sid_hex}"
    _lppdi_next="${__ls_off}"
}

_lsarpc_parse_policy_audit_info() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lppai_out="$3"
    local -n _lppai_next="$4"

    local -i auditing_mode options_ptr max_count
    auditing_mode=$(( 16#${stub:$(( __ls_off * 2 )):2} ))
    (( __ls_off += 1 ))
    (( __ls_off += 3 ))

    endian::read_le32 "${stub}" "${__ls_off}" options_ptr
    (( __ls_off += 4 ))
    endian::read_le32 "${stub}" "${__ls_off}" max_count
    (( __ls_off += 4 ))

    local -a options=()
    if (( options_ptr != 0 && max_count > 0 )); then
        local -i array_count item_count value i
        endian::read_le32 "${stub}" "${__ls_off}" array_count
        (( __ls_off += 4 ))

        item_count="${max_count}"
        (( array_count < item_count )) && item_count="${array_count}"

        for (( i = 0; i < item_count; i++ )); do
            endian::read_le32 "${stub}" "${__ls_off}" value
            options+=("${value}")
            (( __ls_off += 4 ))
        done
    fi

    local opts_csv=""
    if (( ${#options[@]} > 0 )); then
        local IFS=,
        opts_csv="${options[*]}"
    fi

    _lppai_out[auditing_mode]="${auditing_mode}"
    _lppai_out[max_audit_event_count]="${max_count}"
    _lppai_out[event_options_count]="${#options[@]}"
    _lppai_out[event_options]="${opts_csv}"
    _lppai_next="${__ls_off}"
}

_lsarpc_parse_query_info_policy_resp() {
    local stub="${1^^}"
    local -i expected_class="$2"
    local -n _lpqip_out="$3"
    _lpqip_out=()

    local -i stub_len=$(( ${#stub} / 2 ))
    if (( stub_len < 12 )); then
        log::error "lsarpc::query_info_policy : stub trop court (${stub_len}B)"
        return 1
    fi

    local -i status policy_ptr info_class off
    endian::read_le32 "${stub}" $(( stub_len - 4 )) status
    if (( status != 0 )); then
        log::error "lsarpc::query_info_policy : NTSTATUS=0x$(printf '%08X' "${status}")"
        return 1
    fi

    endian::read_le32 "${stub}" 0 policy_ptr
    if (( policy_ptr == 0 )); then
        log::error "lsarpc::query_info_policy : PolicyInformation NULL"
        return 1
    fi

    endian::read_le16 "${stub}" 4 info_class
    if (( expected_class != info_class )); then
        log::error "lsarpc::query_info_policy : classe inattendue=${info_class}"
        return 1
    fi

    _lpqip_out[class]="${info_class}"
    off=8
    case "${info_class}" in
        ${LSARPC_POLICY_INFO_DOMAIN_DNS})
            _lsarpc_parse_policy_dns_info "${stub}" "${off}" _lpqip_out off || return 1
            ;;
        ${LSARPC_POLICY_INFO_AUDIT_EVENTS})
            _lsarpc_parse_policy_audit_info "${stub}" "${off}" _lpqip_out off || return 1
            ;;
        *)
            log::error "lsarpc::query_info_policy : classe ${info_class} non supportée"
            return 1
            ;;
    esac
}

_lsarpc_parse_enum_privileges_resp() {
    local stub="${1^^}"
    local -n _lpepr_ctx="$2"
    local -n _lpepr_out="$3"
    local -n _lpepr_status="$4"
    _lpepr_out=()

    local -i stub_len=$(( ${#stub} / 2 ))
    if (( stub_len < 16 )); then
        log::error "lsarpc::enum_privileges : stub trop court (${stub_len}B)"
        return 1
    fi

    local -i off=0 entries priv_ptr array_count item_count i low_part high_part
    endian::read_le32 "${stub}" $(( stub_len - 4 )) _lpepr_status

    endian::read_le32 "${stub}" "${off}" _lpepr_ctx
    (( off += 4 ))
    endian::read_le32 "${stub}" "${off}" entries
    (( off += 4 ))
    endian::read_le32 "${stub}" "${off}" priv_ptr
    (( off += 4 ))

    if (( entries == 0 || priv_ptr == 0 )); then
        return 0
    fi

    endian::read_le32 "${stub}" "${off}" array_count
    (( off += 4 ))

    item_count="${entries}"
    (( array_count < item_count )) && item_count="${array_count}"

    local -a name_ptrs=()
    local -a luid_hex=()
    local _len _ptr

    for (( i = 0; i < item_count; i++ )); do
        _lsarpc_read_ustr_inline "${stub}" "${off}" _len _ptr off
        name_ptrs+=("${_ptr}")

        endian::read_le32 "${stub}" "${off}" low_part
        (( off += 4 ))
        endian::read_le32 "${stub}" "${off}" high_part
        (( off += 4 ))

        luid_hex+=("$(printf '%08X%08X' \
            $(( high_part & 0xFFFFFFFF )) \
            $(( low_part & 0xFFFFFFFF )))")
    done

    for (( i = 0; i < item_count; i++ )); do
        local name=""
        if (( name_ptrs[i] != 0 )); then
            local _next
            _lsarpc_read_ustr "${stub}" "${off}" name _next
            off="${_next}"
        fi
        _lpepr_out+=("${name}:${luid_hex[i]}")
    done
}

_lsarpc_parse_referenced_domains() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lprd_names="$3"
    local -n _lprd_sids="$4"
    local -n _lprd_next="$5"

    _lprd_names=()
    _lprd_sids=()

    local -i entries domains_ptr max_entries array_count item_count sid_ptr i
    endian::read_le32 "${stub}" "${__ls_off}" entries
    (( __ls_off += 4 ))
    endian::read_le32 "${stub}" "${__ls_off}" domains_ptr
    (( __ls_off += 4 ))
    endian::read_le32 "${stub}" "${__ls_off}" max_entries
    (( __ls_off += 4 ))

    if (( entries == 0 || domains_ptr == 0 )); then
        _lprd_next="${__ls_off}"
        return 0
    fi

    endian::read_le32 "${stub}" "${__ls_off}" array_count
    (( __ls_off += 4 ))

    item_count="${entries}"
    (( array_count < item_count )) && item_count="${array_count}"

    local -a name_ptrs=()
    local _len _ptr
    local -i _next_off

    for (( i = 0; i < item_count; i++ )); do
        _lsarpc_read_ustr_inline "${stub}" "${__ls_off}" _len _ptr _next_off
        __ls_off="${_next_off}"
        name_ptrs+=("${_ptr}")

        endian::read_le32 "${stub}" "${__ls_off}" sid_ptr
        _lprd_sids+=("${sid_ptr}")
        (( __ls_off += 4 ))
    done

    for (( i = 0; i < item_count; i++ )); do
        local name="" sid_hex="" _next

        if (( name_ptrs[i] != 0 )); then
            _lsarpc_read_ustr "${stub}" "${__ls_off}" name _next
            __ls_off="${_next}"
        fi

        if (( _lprd_sids[i] != 0 )); then
            _lsarpc_decode_sid "${stub}" "${__ls_off}" sid_hex _next
            __ls_off="${_next}"
        fi

        _lprd_names+=("${name}")
        _lprd_sids[i]="${sid_hex}"
    done

    _lprd_next="${__ls_off}"
}

_lsarpc_parse_translated_names() {
    local stub="${1^^}"
    local -i __ls_off="$2"
    local -n _lptn_domains="$3"
    local -n _lptn_out="$4"
    local -n _lptn_mapped="$5"
    local -n _lptn_next="$6"

    _lptn_out=()

    local -i entries names_ptr array_count item_count i use domain_index_u32 domain_index
    endian::read_le32 "${stub}" "${__ls_off}" entries
    (( __ls_off += 4 ))
    endian::read_le32 "${stub}" "${__ls_off}" names_ptr
    (( __ls_off += 4 ))

    if (( entries == 0 || names_ptr == 0 )); then
        endian::read_le32 "${stub}" "${__ls_off}" _lptn_mapped
        (( __ls_off += 4 ))
        _lptn_next="${__ls_off}"
        return 0
    fi

    endian::read_le32 "${stub}" "${__ls_off}" array_count
    (( __ls_off += 4 ))

    item_count="${entries}"
    (( array_count < item_count )) && item_count="${array_count}"

    local -a uses=()
    local -a name_ptrs=()
    local -a domain_indexes=()
    local _len _ptr
    local -i _next_off

    for (( i = 0; i < item_count; i++ )); do
        endian::read_le16 "${stub}" "${__ls_off}" use
        uses+=("${use}")
        (( __ls_off += 2 ))
        (( __ls_off += 2 ))

        _lsarpc_read_ustr_inline "${stub}" "${__ls_off}" _len _ptr _next_off
        __ls_off="${_next_off}"
        name_ptrs+=("${_ptr}")

        endian::read_le32 "${stub}" "${__ls_off}" domain_index_u32
        _lsarpc_u32_to_s32 "${domain_index_u32}" domain_index
        domain_indexes+=("${domain_index}")
        (( __ls_off += 4 ))
    done

    for (( i = 0; i < item_count; i++ )); do
        local name="" domain="" use_name="" _next

        if (( name_ptrs[i] != 0 )); then
            _lsarpc_read_ustr "${stub}" "${__ls_off}" name _next
            __ls_off="${_next}"
        fi

        if (( domain_indexes[i] >= 0 && domain_indexes[i] < ${#_lptn_domains[@]} )); then
            domain="${_lptn_domains[${domain_indexes[i]}]}"
        fi

        _lsarpc_sid_use_name "${uses[i]}" use_name
        _lptn_out+=("${use_name}:${domain}:${name}")
    done

    endian::read_le32 "${stub}" "${__ls_off}" _lptn_mapped
    (( __ls_off += 4 ))
    _lptn_next="${__ls_off}"
}

_lsarpc_parse_lookup_sids_resp() {
    local stub="${1^^}"
    local -n _lplsr_out="$2"
    local -n _lplsr_mapped="$3"
    local -n _lplsr_status="$4"
    _lplsr_out=()

    local -i stub_len=$(( ${#stub} / 2 ))
    if (( stub_len < 12 )); then
        log::error "lsarpc::lookup_sids : stub trop court (${stub_len}B)"
        return 1
    fi

    endian::read_le32 "${stub}" $(( stub_len - 4 )) _lplsr_status

    local -i off=0 ref_domains_ptr
    endian::read_le32 "${stub}" "${off}" ref_domains_ptr
    (( off += 4 ))

    local -a domain_names=()
    local -a domain_sids=()
    if (( ref_domains_ptr != 0 )); then
        _lsarpc_parse_referenced_domains "${stub}" "${off}" domain_names domain_sids off || return 1
    fi

    _lsarpc_parse_translated_names "${stub}" "${off}" domain_names _lplsr_out _lplsr_mapped off || return 1
}

# -- RPC helpers --------------------------------------------------------------

_lsarpc_rpc_call() {
    local _sess="$1"
    local file_id="$2"
    local -i opnum="$3"
    local stub_hex="$4"
    local -i call_id="$5"
    local -n _lrc_out="$6"

    local rpc_req
    dcerpc::request::build rpc_req "${opnum}" "${stub_hex}" "${call_id}"

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
    local _raw
    smb::_recv "${_sess}" _raw 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${_raw}" ioctl_resp || return 1

    local -A rpc_resp
    dcerpc::request::parse_response "${ioctl_resp[output]}" rpc_resp || return 1

    _lrc_out="${rpc_resp[stub]}"
}

# -- BIND ---------------------------------------------------------------------

lsarpc::bind() {
    local _sess="$1"
    local file_id="$2"

    local -i call_id
    _lsarpc_next_call_id call_id

    local bind_pdu
    dcerpc::bind::build bind_pdu \
        "${DCERPC_IF_LSARPC_UUID}" \
        "${DCERPC_IF_LSARPC_VER_MAJ}" \
        "${DCERPC_IF_LSARPC_VER_MIN}" \
        "${call_id}"

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

    local _bind_raw
    smb::_recv "${_sess}" _bind_raw 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${_bind_raw}" ioctl_resp || return 1

    local -A ack
    dcerpc::bind::parse_ack "${ioctl_resp[output]}" ack || return 1

    log::info "lsarpc : BIND OK -- assoc_grp=${ack[assoc_grp]}"
}

# -- API publique -------------------------------------------------------------

lsarpc::open_policy() {
    local _sess="$1"
    local file_id="$2"
    local -n _lop_out="$3"
    local -i desired_access="${4:-${LSARPC_ACCESS_MAXIMUM_ALLOWED}}"

    local stub resp
    _lsarpc_build_open_policy_stub "${desired_access}" stub

    local -i call_id
    _lsarpc_next_call_id call_id
    _lsarpc_rpc_call "${_sess}" "${file_id}" "${LSARPC_OPNUM_OPEN_POLICY2}" "${stub}" "${call_id}" resp || return 1

    local -i status
    endian::read_le32 "${resp}" 20 status
    if (( status != 0 )); then
        log::error "lsarpc::open_policy : NTSTATUS=0x$(printf '%08X' "${status}")"
        return 1
    fi

    _lop_out="${resp:0:$(( LSARPC_HANDLE_SIZE * 2 ))}"
    log::info "lsarpc : LsarOpenPolicy2 OK"
}

lsarpc::close_handle() {
    local _sess="$1"
    local file_id="$2"
    local handle="${3^^}"

    local -i call_id
    _lsarpc_next_call_id call_id

    local resp
    _lsarpc_rpc_call "${_sess}" "${file_id}" "${LSARPC_OPNUM_CLOSE}" "${handle}" "${call_id}" resp || return 0

    local -i status
    endian::read_le32 "${resp}" 20 status
    (( status == 0 )) || log::warn "lsarpc::close_handle : status=0x$(printf '%08X' "${status}")"
    return 0
}

lsarpc::query_info_policy() {
    local _sess="$1"
    local file_id="$2"
    local policy_handle="${3^^}"
    local -i info_class="$4"
    local -n _lqip_out="$5"

    local stub resp
    _lsarpc_build_query_info_policy_stub "${policy_handle}" "${info_class}" stub

    local -i call_id
    _lsarpc_next_call_id call_id
    _lsarpc_rpc_call "${_sess}" "${file_id}" "${LSARPC_OPNUM_QUERY_INFO_POLICY2}" "${stub}" "${call_id}" resp || return 1

    _lsarpc_parse_query_info_policy_resp "${resp}" "${info_class}" _lqip_out
}

lsarpc::enum_privileges() {
    local _sess="$1"
    local file_id="$2"
    local policy_handle="${3^^}"
    local -n _lep_out="$4"
    _lep_out=()

    local -i enum_context=0 status=0 call_id

    while true; do
        local stub resp
        _lsarpc_build_enum_privileges_stub "${policy_handle}" "${enum_context}" "${LSARPC_PREF_MAX_LENGTH}" stub

        _lsarpc_next_call_id call_id
        _lsarpc_rpc_call "${_sess}" "${file_id}" "${LSARPC_OPNUM_ENUM_PRIVILEGES}" "${stub}" "${call_id}" resp || return 1

        local -a batch=()
        _lsarpc_parse_enum_privileges_resp "${resp}" enum_context batch status || return 1
        (( ${#batch[@]} > 0 )) && _lep_out+=("${batch[@]}")

        if (( status == 0 )); then
            break
        elif (( status == LSARPC_STATUS_MORE_ENTRIES )); then
            continue
        else
            log::error "lsarpc::enum_privileges : NTSTATUS=0x$(printf '%08X' "${status}")"
            return 1
        fi
    done
}

lsarpc::lookup_sids() {
    local _sess="$1"
    local file_id="$2"
    local policy_handle="${3^^}"
    local -n _lls_sids="$4"
    local -n _lls_out="$5"
    _lls_out=()

    local stub resp
    _lsarpc_build_lookup_sids_stub "${policy_handle}" _lls_sids stub

    local -i call_id
    _lsarpc_next_call_id call_id
    _lsarpc_rpc_call "${_sess}" "${file_id}" "${LSARPC_OPNUM_LOOKUP_SIDS}" "${stub}" "${call_id}" resp || return 1

    local -i mapped_count status
    _lsarpc_parse_lookup_sids_resp "${resp}" _lls_out mapped_count status || return 1

    if (( status == 0 )); then
        :
    elif (( status == LSARPC_STATUS_SOME_NOT_MAPPED )); then
        log::debug "lsarpc::lookup_sids : résolution partielle (${mapped_count} mappé(s))"
    elif (( status == LSARPC_STATUS_NONE_MAPPED )); then
        log::debug "lsarpc::lookup_sids : aucun SID mappé"
    else
        log::error "lsarpc::lookup_sids : NTSTATUS=0x$(printf '%08X' "${status}")"
        return 1
    fi
}
