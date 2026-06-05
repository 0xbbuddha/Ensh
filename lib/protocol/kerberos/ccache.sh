#!/usr/bin/env bash
#
# lib/protocol/kerberos/ccache.sh - MIT ccache v4 (FILE: credential cache)
#
# Lecture et ecriture du format MIT ccache v4 pour interoperabilite avec
# impacket, kinit, et les outils Kerberos standard.
#
# Cas d'usage :
#   - Charger un TGT impacket pour l'utiliser dans Ensh
#   - Sauvegarder un ticket obtenu pour pass-the-ticket
#   - Exporter en base64 pour transmission
#
# Format reference : MIT krb5 ccache v4 (big-endian)
#
# API publique :
#   ccache::read       <file_path> <var_dict_out>
#   ccache::write      <file_path> <realm> <principal> <sname> \
#                      <ticket_hex> <session_key_hex> <etype_int> \
#                      [auth_time] [end_time] [renew_till] [flags_hex]
#   ccache::list       <file_path>
#   ccache::export_b64 <file_path> <var_out>
#
# Dependances : core/endian, core/log, core/hex, encoding/base64, encoding/utf16
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_KRB_CCACHE:-}" ]] && return 0
readonly _ENSH_KRB_CCACHE=1

ensh::import core/endian
ensh::import core/log
ensh::import core/hex
ensh::import encoding/base64

# ── Constantes ────────────────────────────────────────────────────────────────

readonly CCACHE_VERSION=0x0504
readonly CCACHE_NAMETYPE_PRINCIPAL=1
readonly CCACHE_NAMETYPE_SRV_INST=2

readonly CCACHE_ETYPE_RC4_HMAC=23
readonly CCACHE_ETYPE_AES128=17
readonly CCACHE_ETYPE_AES256=18

readonly CCACHE_FLAG_FORWARDABLE=0x40000000
readonly CCACHE_FLAG_PROXIABLE=0x20000000
readonly CCACHE_FLAG_RENEWABLE=0x00800000

# Retour global d'offset pour les helpers de lecture - evite les conflits nameref
_CC_NEXT=0

# ── Helpers big-endian ────────────────────────────────────────────────────────

_cc_r16() { printf -v "$3" '%d' "$(( 16#${1:$(( $2 * 2 )):4} ))"; }
_cc_r32() { printf -v "$3" '%d' "$(( 16#${1:$(( $2 * 2 )):8} ))"; }
_cc_w16() { printf -v "$2" '%04X' "$1"; }
_cc_w32() { printf -v "$2" '%08X' "$1"; }

# _cc_read_cstr <hex_msg> <offset_bytes> <result_var_name>
# Lit une chaine uint32 BE + ASCII bytes. Stocke le resultat dans $3,
# met a jour _CC_NEXT avec l'offset suivant.
_cc_read_cstr() {
    local _crc_msg="$1"; local -i _crc_off="$2"
    local -i _crc_len=$(( 16#${_crc_msg:$(( _crc_off * 2 )):8} ))
    (( _crc_off += 4 ))
    local _crc_hex="${_crc_msg:$(( _crc_off * 2 )):$(( _crc_len * 2 ))}"
    local _crc_str; hex::to_string "${_crc_hex}" _crc_str
    printf -v "$3" '%s' "${_crc_str}"
    _CC_NEXT=$(( _crc_off + _crc_len ))
}

# _cc_write_cstr <ascii_str> <result_var_name>
# Encode uint32 BE + ASCII bytes dans $2.
_cc_write_cstr() {
    local _cwc_str="$1"
    local _cwc_hex; hex::from_string "${_cwc_str}" _cwc_hex
    local _cwc_len_hex; _cc_w32 "${#_cwc_str}" _cwc_len_hex
    printf -v "$2" '%s' "${_cwc_len_hex}${_cwc_hex}"
}

# _cc_read_principal <hex_msg> <offset_bytes> <name_var> <realm_var>
# Lit un principal ccache. Met a jour _CC_NEXT.
_cc_read_principal() {
    local _crp_msg="$1"; local -i _crp_off="$2"

    local -i _crp_name_type _crp_num_comps
    _cc_r32 "${_crp_msg}" "${_crp_off}" _crp_name_type; (( _crp_off += 4 ))
    _cc_r32 "${_crp_msg}" "${_crp_off}" _crp_num_comps; (( _crp_off += 4 ))

    _cc_read_cstr "${_crp_msg}" "${_crp_off}" "$4"  # realm
    _crp_off="${_CC_NEXT}"

    local -a _crp_comps=()
    local -i _crp_i
    for (( _crp_i=0; _crp_i<_crp_num_comps; _crp_i++ )); do
        local _crp_comp
        _cc_read_cstr "${_crp_msg}" "${_crp_off}" _crp_comp
        _crp_off="${_CC_NEXT}"
        _crp_comps+=("${_crp_comp}")
    done

    local _crp_realm; _cc_r32 "${_crp_msg}" 0 _crp_realm 2>/dev/null || true
    # Nom compose des composants joints par '/'
    local _crp_joined; _crp_joined="$(IFS='/'; printf '%s' "${_crp_comps[*]}")"
    # Lire la valeur de realm depuis $4
    local _crp_realm_val="${!4}"
    printf -v "$3" '%s' "${_crp_joined}@${_crp_realm_val}"
    _CC_NEXT="${_crp_off}"
}

# _cc_write_principal <realm> <components_slash_sep> <name_type> <result_var>
_cc_write_principal() {
    local _cwp_realm="$1"; local _cwp_comps_str="$2"; local -i _cwp_name_type="$3"

    IFS='/' read -ra _cwp_comps <<< "${_cwp_comps_str%%@*}"
    local -i _cwp_nc="${#_cwp_comps[@]}"

    local _cwp_nt _cwp_nc_hex _cwp_realm_hex
    _cc_w32 "${_cwp_name_type}" _cwp_nt
    _cc_w32 "${_cwp_nc}"        _cwp_nc_hex
    _cc_write_cstr "${_cwp_realm}" _cwp_realm_hex

    local _cwp_out="${_cwp_nt}${_cwp_nc_hex}${_cwp_realm_hex}"
    for _cwp_c in "${_cwp_comps[@]}"; do
        local _cwp_c_hex; _cc_write_cstr "${_cwp_c}" _cwp_c_hex
        _cwp_out+="${_cwp_c_hex}"
    done
    printf -v "$4" '%s' "${_cwp_out}"
}

# ── API publique ─────────────────────────────────────────────────────────────

# ccache::read <file_path> <var_dict_out>
ccache::read() {
    local _ccr_file="$1"
    local -n _ccr_dict="$2"

    [[ -f "${_ccr_file}" ]] || { log::error "ccache::read : fichier introuvable: ${_ccr_file}"; return 1; }

    local _ccr_msg
    _ccr_msg=$(od -An -tx1 -v "${_ccr_file}" | tr -d ' \n' | tr 'a-f' 'A-F')
    [[ -n "${_ccr_msg}" ]] || return 1

    local -i _ccr_off=0 _ccr_msg_bytes=$(( ${#_ccr_msg} / 2 ))

    # Version
    local -i _ccr_ver; _cc_r16 "${_ccr_msg}" 0 _ccr_ver
    (( _ccr_ver == CCACHE_VERSION )) || {
        log::error "ccache::read : version 0x$(printf '%04X' ${_ccr_ver}) non supportee"
        return 1
    }
    _ccr_dict[version]="${_ccr_ver}"
    _ccr_off=2

    # Header tags (sauter)
    local -i _ccr_hlen; _cc_r16 "${_ccr_msg}" "${_ccr_off}" _ccr_hlen
    (( _ccr_off += 2 + _ccr_hlen ))

    # Default principal
    local _ccr_def_name _ccr_def_realm
    _cc_read_principal "${_ccr_msg}" "${_ccr_off}" _ccr_def_name _ccr_def_realm
    _ccr_dict[default_principal]="${_ccr_def_name}"
    _ccr_off="${_CC_NEXT}"

    # Credentials
    local -i _ccr_nc=0
    while (( _ccr_off + 8 < _ccr_msg_bytes )); do
        local _ccr_client _ccr_client_realm
        _cc_read_principal "${_ccr_msg}" "${_ccr_off}" _ccr_client _ccr_client_realm 2>/dev/null || break
        _ccr_off="${_CC_NEXT}"
        (( _ccr_off + 4 >= _ccr_msg_bytes )) && break

        local _ccr_server _ccr_server_realm
        _cc_read_principal "${_ccr_msg}" "${_ccr_off}" _ccr_server _ccr_server_realm 2>/dev/null || break
        _ccr_off="${_CC_NEXT}"

        # keyblock: keytype(2B) + etype(2B) + keylen(2B) + keydata
        local -i _ccr_etype _ccr_klen
        _cc_r16 "${_ccr_msg}" "${_ccr_off}" _ccr_etype; (( _ccr_off += 2 ))
        (( _ccr_off += 2 ))  # etype (redondant dans v4, meme valeur que keytype)
        _cc_r16 "${_ccr_msg}" "${_ccr_off}" _ccr_klen;  (( _ccr_off += 2 ))
        local _ccr_key_hex="${_ccr_msg:$(( _ccr_off * 2 )):$(( _ccr_klen * 2 ))}"
        (( _ccr_off += _ccr_klen ))

        # timestamps
        local -i _ccr_auth _ccr_start _ccr_end _ccr_renew
        _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_auth;  (( _ccr_off += 4 ))
        _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_start; (( _ccr_off += 4 ))
        _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_end;   (( _ccr_off += 4 ))
        _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_renew; (( _ccr_off += 4 ))

        # is_skey + flags
        (( _ccr_off += 1 ))
        local _ccr_flags="${_ccr_msg:$(( _ccr_off * 2 )):8}"
        (( _ccr_off += 4 ))

        # addresses (skip)
        local -i _ccr_naddr; _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_naddr; (( _ccr_off += 4 ))
        local -i _ccr_ai
        for (( _ccr_ai=0; _ccr_ai<_ccr_naddr; _ccr_ai++ )); do
            (( _ccr_off += 2 ))
            local -i _ccr_alen; _cc_r16 "${_ccr_msg}" "${_ccr_off}" _ccr_alen; (( _ccr_off += 2 + _ccr_alen ))
        done

        # authdata (skip)
        local -i _ccr_nad; _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_nad; (( _ccr_off += 4 ))
        local -i _ccr_adi
        for (( _ccr_adi=0; _ccr_adi<_ccr_nad; _ccr_adi++ )); do
            (( _ccr_off += 2 ))
            local -i _ccr_adl; _cc_r16 "${_ccr_msg}" "${_ccr_off}" _ccr_adl; (( _ccr_off += 2 + _ccr_adl ))
        done

        # ticket DER
        local -i _ccr_tlen; _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_tlen; (( _ccr_off += 4 ))
        local _ccr_ticket="${_ccr_msg:$(( _ccr_off * 2 )):$(( _ccr_tlen * 2 ))}"
        (( _ccr_off += _ccr_tlen ))

        # second ticket (skip)
        local -i _ccr_slen; _cc_r32 "${_ccr_msg}" "${_ccr_off}" _ccr_slen; (( _ccr_off += 4 + _ccr_slen ))

        local _n="${_ccr_nc}"
        _ccr_dict[cred_${_n}_client]="${_ccr_client}"
        _ccr_dict[cred_${_n}_server]="${_ccr_server}"
        _ccr_dict[cred_${_n}_etype]="${_ccr_etype}"
        _ccr_dict[cred_${_n}_key_hex]="${_ccr_key_hex}"
        _ccr_dict[cred_${_n}_auth_time]="${_ccr_auth}"
        _ccr_dict[cred_${_n}_end_time]="${_ccr_end}"
        _ccr_dict[cred_${_n}_renew_till]="${_ccr_renew}"
        _ccr_dict[cred_${_n}_flags]="${_ccr_flags}"
        _ccr_dict[cred_${_n}_ticket_hex]="${_ccr_ticket}"
        (( _ccr_nc++ ))
    done

    _ccr_dict[cred_count]="${_ccr_nc}"
    log::debug "ccache::read : ${_ccr_nc} credential(s) depuis ${_ccr_file}"
}

# ccache::write <file_path> <realm> <principal> <sname>
#               <ticket_hex> <session_key_hex> <etype_int>
#               [auth_time] [end_time] [renew_till] [flags_hex]
ccache::write() {
    local _ccw_file="$1"
    local _ccw_realm="${2^^}"
    local _ccw_principal="$3"
    local _ccw_sname="$4"
    local _ccw_ticket="${5^^}"
    local _ccw_key="${6^^}"
    local -i _ccw_etype="$7"
    local -i _ccw_auth="${8:-$(date +%s)}"
    local -i _ccw_end="${9:-$(( _ccw_auth + 36000 ))}"
    local -i _ccw_renew="${10:-$(( _ccw_auth + 604800 ))}"
    local _ccw_flags="${11:-40E10000}"

    # Header
    local _ccw_data="05040000"

    # Default principal (client)
    local _ccw_def; _cc_write_principal "${_ccw_realm}" "${_ccw_principal}" "${CCACHE_NAMETYPE_PRINCIPAL}" _ccw_def
    _ccw_data+="${_ccw_def}"

    # Credential
    local _ccw_cred=""

    # client principal
    local _ccw_client; _cc_write_principal "${_ccw_realm}" "${_ccw_principal}" "${CCACHE_NAMETYPE_PRINCIPAL}" _ccw_client
    _ccw_cred+="${_ccw_client}"

    # server principal
    local _ccw_sname_clean="${_ccw_sname%%@*}"
    local _ccw_server; _cc_write_principal "${_ccw_realm}" "${_ccw_sname_clean}" "${CCACHE_NAMETYPE_SRV_INST}" _ccw_server
    _ccw_cred+="${_ccw_server}"

    # keyblock: keytype(2B) + etype(2B) + keylen(2B) + keydata
    local _ccw_etype_h _ccw_klen_h
    _cc_w16 "${_ccw_etype}" _ccw_etype_h
    _cc_w16 "$(( ${#_ccw_key} / 2 ))" _ccw_klen_h
    # keytype et etype sont identiques dans l'usage courant
    _ccw_cred+="${_ccw_etype_h}${_ccw_etype_h}${_ccw_klen_h}${_ccw_key}"

    # timestamps
    local _ccw_at _ccw_st _ccw_et _ccw_rt
    _cc_w32 "${_ccw_auth}"  _ccw_at
    _cc_w32 "${_ccw_auth}"  _ccw_st
    _cc_w32 "${_ccw_end}"   _ccw_et
    _cc_w32 "${_ccw_renew}" _ccw_rt
    _ccw_cred+="${_ccw_at}${_ccw_st}${_ccw_et}${_ccw_rt}"

    # is_skey + flags + addresses=0 + authdata=0
    _ccw_cred+="00${_ccw_flags^^}0000000000000000"

    # ticket DER
    local _ccw_tlen; _cc_w32 "$(( ${#_ccw_ticket} / 2 ))" _ccw_tlen
    _ccw_cred+="${_ccw_tlen}${_ccw_ticket}"

    # second ticket empty
    _ccw_cred+="00000000"

    local _ccw_full="${_ccw_data}${_ccw_cred}"
    printf '%s' "${_ccw_full}" | xxd -r -p > "${_ccw_file}" || {
        log::error "ccache::write : impossible d'ecrire ${_ccw_file}"
        return 1
    }

    log::info "ccache::write : ticket ecrit dans ${_ccw_file} ($(( ${#_ccw_full}/2 ))B)"
}

# ccache::list <file_path>
ccache::list() {
    declare -A _ccl_dict
    ccache::read "$1" _ccl_dict || return 1

    printf 'Ccache : %s\n' "$1"
    printf 'Principal : %s\n\n' "${_ccl_dict[default_principal]:-?}"

    local -i _ccl_n="${_ccl_dict[cred_count]:-0}" _ccl_i
    for (( _ccl_i=0; _ccl_i<_ccl_n; _ccl_i++ )); do
        local _ccl_et="${_ccl_dict[cred_${_ccl_i}_etype]:-?}"
        local _ccl_ename
        case "${_ccl_et}" in
            17) _ccl_ename="aes128-cts-hmac-sha1-96" ;;
            18) _ccl_ename="aes256-cts-hmac-sha1-96" ;;
            23) _ccl_ename="arcfour-hmac" ;;
            *)  _ccl_ename="etype-${_ccl_et}" ;;
        esac
        local _ccl_end="${_ccl_dict[cred_${_ccl_i}_end_time]:-0}"
        local _ccl_expiry="?"
        (( _ccl_end > 0 )) && _ccl_expiry=$(date -d "@${_ccl_end}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf '%d' "${_ccl_end}")

        printf '[%d] %s\n' "${_ccl_i}" "${_ccl_dict[cred_${_ccl_i}_server]:-?}"
        printf '    client : %s\n'  "${_ccl_dict[cred_${_ccl_i}_client]:-?}"
        printf '    etype  : %s\n'  "${_ccl_ename}"
        printf '    expire : %s\n'  "${_ccl_expiry}"
        local _ccl_tkt="${_ccl_dict[cred_${_ccl_i}_ticket_hex]:-}"
        printf '    ticket : %dB\n' "$(( ${#_ccl_tkt} / 2 ))"
    done
}

# ccache::export_b64 <file_path> <var_out>
ccache::export_b64() {
    [[ -f "$1" ]] || return 1
    local _cceb_hex
    _cceb_hex=$(od -An -tx1 -v "$1" | tr -d ' \n' | tr 'a-f' 'A-F')
    base64::encode_hex "${_cceb_hex}" "$2"
}
