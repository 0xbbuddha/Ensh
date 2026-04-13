#!/usr/bin/env bash
#
# lib/protocol/smb/smb3/signing.sh — Signature SMB 3.x (dialectes ≥ 0x0300)
#
# Hors scope SMB 2.0.2 / 2.1 (HMAC) : voir protocol/smb/smb2/signing.sh.
#
# Dérivation SigningKey (MS-SMB2 §3.2.5.3, aligné impacket / Windows) :
#   SMB 3.0 / 3.0.2 : KDF(..., Label="SMB2AESCMAC\0", Context="SmbSign\0", L=128)
#   SMB 3.1.1       : KDF(..., Label="SMBSigningKey\0", Context=PreauthIntegrityHashValue)
#                     (Preauth requis si negotiate 3.1.1 est implémenté.)
#
# Signature : AES-128-CMAC sur le message SMB2 entier (en-tête 64 octets + corps),
#   avec SMB2_FLAGS_SIGNED et champ Signature à zéro pour le calcul (MS-SMB2 §3.2.5.3).
#
# Dépendances : core/endian, core/log, crypto/hmac_sha256, crypto/aes_cmac
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB3_SIGNING:-}" ]] && return 0
readonly _ENSH_SMB3_SIGNING=1

ensh::import core/endian
ensh::import core/log
ensh::import crypto/hmac_sha256
ensh::import crypto/aes_cmac

readonly _SMB3_KDF_LABEL_AESCMAC="534D4232414553434D414300"      # "SMB2AESCMAC\0"
readonly _SMB3_KDF_CONTEXT_SMBSIGN="536D625369676E00"             # "SmbSign\0"
readonly _SMB3_KDF_LABEL_SIGNING="534D425369676E696E674B657900"   # "SMBSigningKey\0"

# smb3::signing::derive_key <var_out> <exported_session_key_hex>
#                            <dialect_int> <session_id_or_preauth_hex128>
#
# Dialectes : 0x0300, 0x0302, 0x0311 uniquement.
smb3::signing::derive_key() {
    local -n _smb3_sk_out="$1"
    local esk="${2^^}"
    local -i dialect="$3"
    local session_id="${4^^}"

    if (( dialect != 0x0300 && dialect != 0x0302 && dialect != 0x0311 )); then
        log::error "smb3::signing::derive_key : dialecte 0x$(printf '%04X' "${dialect}") — utiliser smb2::signing pour 2.0.2 / 2.1"
        return 1
    fi

    local kdf_input=""

    if (( dialect == 0x0311 )); then
        if [[ ${#session_id} -ne 128 ]]; then
            log::error "smb3::signing::derive_key : 3.1.1 — PreauthIntegrityHashValue (128 nibbles hex) requis"
            return 1
        fi
        kdf_input+="00000001"
        kdf_input+="${_SMB3_KDF_LABEL_SIGNING}"
        kdf_input+="00"
        kdf_input+="${session_id}"
        kdf_input+="00000080"
    else
        kdf_input+="00000001"
        kdf_input+="${_SMB3_KDF_LABEL_AESCMAC}"
        kdf_input+="00"
        kdf_input+="${_SMB3_KDF_CONTEXT_SMBSIGN}"
        kdf_input+="00000080"
    fi

    local kdf_result
    hmac_sha256::compute "${esk}" "${kdf_input}" kdf_result || return 1

    _smb3_sk_out="${kdf_result:0:32}"
    log::debug "smb3::signing : SigningKey (0x$(printf '%04X' "${dialect}")) = ${_smb3_sk_out}"
}

# smb3::signing::sign <var_msg_inout> <signing_key_hex>
smb3::signing::sign() {
    local -n _smb3_sign_msg="$1"
    local signing_key="${2^^}"
    local msg="${_smb3_sign_msg^^}"

    if [[ "${msg:0:8}" != "FE534D42" ]]; then
        log::error "smb3::signing::sign : en-tête SMB invalide"
        return 1
    fi

    local -i _cur_flags; endian::read_le32 "${msg}" 16 _cur_flags
    local _new_flags_le; endian::le32 "$(( _cur_flags | 0x00000008 ))" _new_flags_le
    msg="${msg:0:32}${_new_flags_le}${msg:40}"

    msg="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    local mac
    aes_cmac::compute "${signing_key}" "${msg}" mac || return 1

    msg="${msg:0:96}${mac:0:32}${msg:128}"

    _smb3_sign_msg="${msg}"
    log::debug "smb3::signing : signé — sig=${mac:0:16}..."
}

# smb3::signing::sign_nbt <var_nbt_msg_inout> <signing_key_hex>
smb3::signing::sign_nbt() {
    local -n _smb3_snbt_msg="$1"
    local signing_key="$2"
    local nbt_msg="${_smb3_snbt_msg^^}"

    local nbt_hdr="${nbt_msg:0:8}"
    local smb2_payload="${nbt_msg:8}"

    smb3::signing::sign smb2_payload "${signing_key}" || return 1

    _smb3_snbt_msg="${nbt_hdr}${smb2_payload}"
}

# smb3::signing::verify <msg_hex> <signing_key_hex> → retcode
smb3::signing::verify() {
    local msg="${1^^}"
    local signing_key="${2^^}"

    local received_sig="${msg:96:32}"
    local msg_zeroed="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    local expected_mac
    aes_cmac::compute "${signing_key}" "${msg_zeroed}" expected_mac || return 1

    local expected_sig="${expected_mac:0:32}"
    if [[ "${received_sig^^}" == "${expected_sig^^}" ]]; then
        return 0
    fi

    log::debug "smb3::signing::verify : ÉCHEC sig_reçue=${received_sig} attendue=${expected_sig}"
    return 1
}
