#!/usr/bin/env bash
#
# lib/protocol/msrpc/samr.sh — MSRPC Security Account Manager Remote (SAMR)
#
# Énumère les utilisateurs d'un domaine via le named pipe \samr.
# Implémente :
#   - SamrConnect (OpNum 0)                    — handle serveur SAM
#   - SamrCloseHandle (OpNum 1)                — libère un handle
#   - SamrLookupDomainInSamServer (OpNum 5)    — SID du domaine
#   - SamrOpenDomain (OpNum 7)                 — handle domaine
#   - SamrEnumerateUsersInDomain (OpNum 13)    — liste des utilisateurs
#
# Flux d'utilisation :
#   1. smb::session::open_pipe sess "\samr" file_id
#   2. samr::bind sess file_id
#   3. samr::connect sess file_id server_handle
#   4. samr::lookup_domain sess file_id server_handle domain_name sid_hex
#   5. samr::open_domain sess file_id server_handle sid_hex domain_handle
#   6. samr::enumerate_users sess file_id domain_handle users_out
#   7. samr::close_handle sess file_id domain_handle
#   8. samr::close_handle sess file_id server_handle
#   9. smb::session::close_pipe sess file_id
#
# NDR32 : encodage little-endian, pointeurs conformants, tableaux conformants.
# Context handles SAMR : 20 octets opaques (Attributes 4B + UUID 16B).
# RPC_UNICODE_STRING inline : Length(2) + MaxLen(2) + unique ptr(4)
#   suivi données déférées : MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE + pad.
#
# Référence : MS-SAMR
#
# Dépendances : core/endian, core/log, encoding/utf16, protocol/dcerpc/bind,
#               protocol/dcerpc/request
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_MSRPC_SAMR:-}" ]] && return 0
readonly _ENSH_MSRPC_SAMR=1

ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/dcerpc/bind
ensh::import protocol/dcerpc/request
ensh::import protocol/smb/smb2/header

# ── Constantes SAMR ──────────────────────────────────────────────────────────

readonly SAMR_OPNUM_CONNECT=0
readonly SAMR_OPNUM_CLOSE_HANDLE=1
readonly SAMR_OPNUM_LOOKUP_DOMAIN=5
readonly SAMR_OPNUM_OPEN_DOMAIN=7
readonly SAMR_OPNUM_ENUM_USERS=13

readonly SAMR_ACCESS_MAXIMUM_ALLOWED=0x02000000
readonly SAMR_USER_NORMAL_ACCOUNT=0x00000010
readonly SAMR_PREF_MAX_LENGTH=0xFFFFFFFF
readonly SAMR_STATUS_MORE_ENTRIES=0x00000105

# Taille d'un context handle NDR32 (20 octets = 40 nibbles)
readonly SAMR_HANDLE_SIZE=20

# Compteur de referent IDs NDR32 — réinitialisé à chaque appel de haut niveau
_SAMR_REF_ID=0x00020000

# ── Helpers NDR32 ────────────────────────────────────────────────────────────

# _samr_next_ref <var_out>
# Retourne le prochain referent ID (LE32) et incrémente le compteur.
_samr_next_ref() {
    local -n _snr_out="$1"
    endian::le32 "${_SAMR_REF_ID}" _snr_out
    (( _SAMR_REF_ID++ ))
}

# _samr_encode_ustr_ptr <var_header_out> <var_deferred_out> <string>
#
# Encode une RPC_UNICODE_STRING avec pointeur unique :
#   header_out  : Length(2B) + MaxLen(2B) + referent(4B)   [inline dans stub]
#   deferred_out: MaxCount(4B) + Offset(4B) + ActualCount(4B) + UTF-16LE + pad
_samr_encode_ustr_ptr() {
    local -n _seuptr_hdr="$1"
    local -n _seuptr_def="$2"
    local str="$3"

    local utf16
    utf16::encode_le "${str}" utf16
    local -i char_count=$(( ${#utf16} / 4 ))
    local -i byte_len=$(( char_count * 2 ))

    local len_le maxlen_le ref
    endian::le16 "${byte_len}"         len_le
    endian::le16 "${byte_len}"         maxlen_le
    _samr_next_ref ref

    # RPC_UNICODE_STRING transporte ici les caractères effectifs uniquement :
    # pas de NUL implicite dans le buffer déféré pour SamrLookupDomainInSamServer.
    local maxcount_le offset_le actual_le
    endian::le32 "${char_count}"       maxcount_le
    endian::le32 0                     offset_le
    endian::le32 "${char_count}"       actual_le

    local -i pad=$(( (4 - (byte_len % 4)) % 4 ))
    local padding=""
    (( pad > 0 )) && printf -v padding '%0*d' $(( pad * 2 )) 0

    _seuptr_hdr="${len_le}${maxlen_le}${ref}"
    _seuptr_def="${maxcount_le}${offset_le}${actual_le}${utf16}${padding}"
}

# _samr_read_ustr <stub_hex> <offset_bytes> <var_str_out> <var_next_out>
#
# Lit les données déférées d'une RPC_UNICODE_STRING
# (MaxCount + Offset + ActualCount + UTF-16LE + pad).
_samr_read_ustr() {
    local stub="${1^^}"
    local -i off="$2"
    local -n _sru_str="$3"
    local -n _sru_next="$4"

    local _max _actual
    endian::read_le32 "${stub}" "${off}" _max;    (( off += 4 ))
    (( off += 4 ))  # Offset (toujours 0)
    endian::read_le32 "${stub}" "${off}" _actual; (( off += 4 ))

    local -i byte_count=$(( _actual * 2 ))
    local utf16_hex="${stub:$(( off * 2 )):$(( byte_count * 2 ))}"
    (( off += byte_count ))

    local -i pad=$(( (4 - (byte_count % 4)) % 4 ))
    (( off += pad ))

    utf16::decode_le "${utf16_hex}" _sru_str
    _sru_next="${off}"
}

# _samr_encode_sid <var_out> <sid_hex>
#
# Encode un RPC_SID pour NDR32 (layout conformant array) :
#   MaxCount(4B) + Revision(1B) + SubAuthorityCount(1B) + IdentifierAuthority(6B)
#   + SubAuthority[n](4B each)
# <sid_hex> : octets bruts du SID en hex, ex: "010500000000000515000000..."
_samr_encode_sid() {
    local -n _ses_out="$1"
    local sid_hex="${2^^}"

    local -i sub_count=$(( 16#${sid_hex:2:2} ))
    local count_le; endian::le32 "${sub_count}" count_le
    _ses_out="${count_le}${sid_hex}"
}

# _samr_decode_sid <stub_hex> <offset_bytes> <var_sid_hex_out> <var_next_out>
#
# Lit un RPC_SID depuis le stub NDR32 (MaxCount + SID bytes).
# Retourne les octets bruts du SID (sans le MaxCount).
_samr_decode_sid() {
    local stub="${1^^}"
    local -i off="$2"
    local -n _sds_hex="$3"
    local -n _sds_next="$4"

    local _sub_count
    endian::read_le32 "${stub}" "${off}" _sub_count; (( off += 4 ))

    # Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthority[n](4n)
    local -i sid_bytes=$(( 8 + _sub_count * 4 ))
    _sds_hex="${stub:$(( off * 2 )):$(( sid_bytes * 2 ))}"
    (( off += sid_bytes ))

    _sds_next="${off}"
}

# ── Helper interne : appel RPC via IOCTL ─────────────────────────────────────

# _samr_rpc_call <sess> <file_id> <opnum> <stub_hex> <call_id> <var_resp_stub_out>
_samr_rpc_call() {
    local _sess="$1"
    local file_id="$2"
    local -i opnum="$3"
    local stub_hex="$4"
    local -i call_id="$5"
    local -n _src_out="$6"

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
    local _src_raw; smb::_recv "${_sess}" _src_raw 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${_src_raw}" ioctl_resp || return 1

    local -A rpc_resp
    dcerpc::request::parse_response "${ioctl_resp[output]}" rpc_resp || return 1

    _src_out="${rpc_resp[stub]}"
}

# ── BIND ─────────────────────────────────────────────────────────────────────

# samr::bind <sess> <file_id>
samr::bind() {
    local _sess="$1"
    local file_id="$2"

    local bind_pdu
    dcerpc::bind::build bind_pdu \
        "${DCERPC_IF_SAMR_UUID}" \
        "${DCERPC_IF_SAMR_VER_MAJ}" \
        "${DCERPC_IF_SAMR_VER_MIN}" \
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
    local _bind_raw; smb::_recv "${_sess}" _bind_raw 15 || return 1

    local -A ioctl_resp
    smb2::ioctl::parse_response "${_bind_raw}" ioctl_resp || return 1

    local -A ack
    dcerpc::bind::parse_ack "${ioctl_resp[output]}" ack || return 1

    log::info "samr : BIND OK — assoc_grp=${ack[assoc_grp]}"
}

# ── SamrConnect (OpNum 0) ────────────────────────────────────────────────────

# samr::connect <sess> <file_id> <var_handle_out>
#
# Appelle SamrConnect (NULL ServerName) pour obtenir un handle serveur SAM.
# <var_handle_out> : reçoit le context handle (40 nibbles hex).
samr::connect() {
    local _sess="$1"
    local file_id="$2"
    local -n _sc_out="$3"

    # ServerName : NULL unique pointer (0x00000000)
    # DesiredAccess : MAXIMUM_ALLOWED
    local access_le; endian::le32 "${SAMR_ACCESS_MAXIMUM_ALLOWED}" access_le
    local stub="00000000${access_le}"

    local resp
    _samr_rpc_call "${_sess}" "${file_id}" "${SAMR_OPNUM_CONNECT}" "${stub}" 1 resp || return 1

    # Response : ServerHandle (20B) + ReturnValue (4B)
    local -i status; endian::read_le32 "${resp}" 20 status
    if (( status != 0 )); then
        log::error "samr::connect : NTSTATUS=0x$(printf '%08X' ${status})"
        return 1
    fi

    _sc_out="${resp:0:$(( SAMR_HANDLE_SIZE * 2 ))}"
    log::info "samr : SamrConnect OK"
}

# ── SamrCloseHandle (OpNum 1) ────────────────────────────────────────────────

# samr::close_handle <sess> <file_id> <handle_hex>
samr::close_handle() {
    local _sess="$1"
    local file_id="$2"
    local handle="${3^^}"

    local resp
    _samr_rpc_call "${_sess}" "${file_id}" "${SAMR_OPNUM_CLOSE_HANDLE}" "${handle}" 2 resp || return 0

    local -i status; endian::read_le32 "${resp}" 20 status
    (( status == 0 )) || log::warn "samr::close_handle : status=0x$(printf '%08X' ${status})"
    return 0
}

# ── SamrLookupDomainInSamServer (OpNum 5) ────────────────────────────────────

# samr::lookup_domain <sess> <file_id> <server_handle> <domain_name> <var_sid_hex_out>
#
# Retourne le SID du domaine sous forme de bytes hex bruts.
samr::lookup_domain() {
    local _sess="$1"
    local file_id="$2"
    local srv_handle="${3^^}"
    local domain_name="$4"
    local -n _sld_sid="$5"

    _SAMR_REF_ID=0x00020000

    # ServerHandle (20B) + Name inline RPC_UNICODE_STRING + données déférées
    local ustr_hdr ustr_def
    _samr_encode_ustr_ptr ustr_hdr ustr_def "${domain_name}"

    local stub="${srv_handle}${ustr_hdr}${ustr_def}"

    local resp
    _samr_rpc_call "${_sess}" "${file_id}" "${SAMR_OPNUM_LOOKUP_DOMAIN}" "${stub}" 3 resp || return 1

    # Windows utilise l'immediate deferral NDR32 :
    # les données SID déférées suivent IMMÉDIATEMENT le ptr, avant le ReturnValue.
    # Layout : [0-3] DomainId ptr | [4-N] SID déféré | [fin-3..fin] ReturnValue
    local -i _sl_stub_len=$(( ${#resp} / 2 ))
    local -i status; endian::read_le32 "${resp}" $(( _sl_stub_len - 4 )) status
    if (( status != 0 )); then
        log::error "samr::lookup_domain : NTSTATUS=0x$(printf '%08X' ${status})"
        return 1
    fi

    local _sid_ptr; endian::read_le32 "${resp}" 0 _sid_ptr
    if (( _sid_ptr == 0 )); then
        log::error "samr::lookup_domain : DomainId pointer NULL"
        return 1
    fi

    # SID déféré immédiatement après le ptr (offset 4)
    local _next
    _samr_decode_sid "${resp}" 4 _sld_sid _next

    log::info "samr : domaine '${domain_name}' SID=${_sld_sid:0:8}..."
}

# ── SamrOpenDomain (OpNum 7) ─────────────────────────────────────────────────

# samr::open_domain <sess> <file_id> <server_handle> <sid_hex> <var_domain_handle_out>
samr::open_domain() {
    local _sess="$1"
    local file_id="$2"
    local srv_handle="${3^^}"
    local sid_hex="${4^^}"
    local -n _sod_out="$5"

    _SAMR_REF_ID=0x00020000

    local access_le; endian::le32 "${SAMR_ACCESS_MAXIMUM_ALLOWED}" access_le

    # DomainId : RPC_SID inline (pas de unique pointer — Windows traite PRPC_SID
    # comme ref pointer implicite pour les paramètres [in] obligatoires)
    local sid_enc
    _samr_encode_sid sid_enc "${sid_hex}"

    local stub="${srv_handle}${access_le}${sid_enc}"

    local resp
    _samr_rpc_call "${_sess}" "${file_id}" "${SAMR_OPNUM_OPEN_DOMAIN}" "${stub}" 4 resp || return 1

    # Response : DomainHandle (20B) + ReturnValue (4B)
    local -i status; endian::read_le32 "${resp}" 20 status
    if (( status != 0 )); then
        log::error "samr::open_domain : NTSTATUS=0x$(printf '%08X' ${status})"
        return 1
    fi

    _sod_out="${resp:0:$(( SAMR_HANDLE_SIZE * 2 ))}"
    log::info "samr : SamrOpenDomain OK"
}

# ── SamrEnumerateUsersInDomain (OpNum 13) ────────────────────────────────────

# samr::enumerate_users <sess> <file_id> <domain_handle> <var_list_out>
#
# <var_list_out> : tableau indexé, entrées "RID:NOM"
# Gère automatiquement STATUS_MORE_ENTRIES (pagination).
samr::enumerate_users() {
    local _sess="$1"
    local file_id="$2"
    local dom_handle="${3^^}"
    local -n _seu_out="$4"
    _seu_out=()

    local -i enum_ctx=0
    local -i call_id=5

    while true; do
        local enum_ctx_le uac_le pref_le
        endian::le32 "${enum_ctx}"                  enum_ctx_le
        endian::le32 "${SAMR_USER_NORMAL_ACCOUNT}"  uac_le
        endian::le32 "${SAMR_PREF_MAX_LENGTH}"      pref_le

        # DomainHandle(20B) + EnumerationContext(4B) + UserAccountControl(4B)
        # + PreferedMaximumLength(4B)
        # EnumerationContext est [in,out] DWORD : valeur directe (pas de pointeur)
        local stub="${dom_handle}${enum_ctx_le}${uac_le}${pref_le}"

        local resp
        _samr_rpc_call "${_sess}" "${file_id}" "${SAMR_OPNUM_ENUM_USERS}" "${stub}" "${call_id}" resp \
            || return 1

        # Immediate deferral : CountReturned et ReturnValue sont en FIN de stub,
        # après toutes les données déférées du Buffer.
        local -i _eu_stub_len=$(( ${#resp} / 2 ))
        local -i status; endian::read_le32 "${resp}" $(( _eu_stub_len - 4 )) status

        _samr_parse_enum_users "${resp}" _seu_out enum_ctx

        if (( status == 0 )); then
            break
        elif (( status == SAMR_STATUS_MORE_ENTRIES )); then
            (( call_id++ ))
            continue
        else
            log::error "samr::enumerate_users : NTSTATUS=0x$(printf '%08X' ${status})"
            return 1
        fi
    done

    log::info "samr : ${#_seu_out[@]} utilisateur(s) énuméré(s)"
}

# _samr_parse_enum_users <stub_hex> <var_list_inout> <var_enum_ctx_out>
#
# Parse le stub NDR32 de SamrEnumerateUsersInDomain (immediate deferral Windows).
# Layout :
#   [0-3]   EnumCtx
#   [4-7]   Buffer outer ptr
#   [8-...]  données déférées du Buffer (EntriesRead + InnerPtr + array + strings)
#   [fin-7..fin-4] CountReturned
#   [fin-3..fin]   ReturnValue  ← déjà lu par l'appelant
_samr_parse_enum_users() {
    local stub="${1^^}"
    local -n _speu_list="$2"
    local -n _speu_ctx="$3"

    endian::read_le32 "${stub}" 0 _speu_ctx

    local _buf_ptr; endian::read_le32 "${stub}" 4 _buf_ptr
    if (( _buf_ptr == 0 )); then
        return 0
    fi

    # Données déférées du Buffer ptr immédiatement après (offset 8)
    local -i off=8

    # SAMPR_ENUMERATION_BUFFER : EntriesRead(4B) + InnerPtr(4B)
    local _entries_read; endian::read_le32 "${stub}" "${off}" _entries_read; (( off += 4 ))
    local _arr_ptr;      endian::read_le32 "${stub}" "${off}" _arr_ptr;      (( off += 4 ))

    if (( _arr_ptr == 0 || _entries_read == 0 )); then
        return 0
    fi

    # Tableau conformant : MaxCount(4B) + [_entries_read] SAMPR_RID_ENUMERATION
    local _max_count; endian::read_le32 "${stub}" "${off}" _max_count; (( off += 4 ))

    # Lire les entrées inline : RelativeId(4B) + Name RPC_UNICODE_STRING(8B)
    local -a rids=()
    local -a name_ptrs=()
    local -i i

    for (( i = 0; i < _entries_read; i++ )); do
        local _rid; endian::read_le32 "${stub}" "${off}" _rid; (( off += 4 ))
        rids+=("${_rid}")

        (( off += 2 ))  # Name.Length
        (( off += 2 ))  # Name.MaximumLength
        local _nptr; endian::read_le32 "${stub}" "${off}" _nptr; (( off += 4 ))
        name_ptrs+=("${_nptr}")
    done

    # Lire les données déférées des chaînes dans l'ordre
    for (( i = 0; i < _entries_read; i++ )); do
        if (( name_ptrs[i] != 0 )); then
            local _name _next
            _samr_read_ustr "${stub}" "${off}" _name _next
            off="${_next}"
            _speu_list+=("${rids[i]}:${_name}")
        else
            _speu_list+=("${rids[i]}:")
        fi
    done
}
