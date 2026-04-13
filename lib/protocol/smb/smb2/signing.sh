#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/signing.sh — Signature SMB 2.0.2 / 2.1 uniquement
#
# Dialectes 0x0202 et 0x0210 : SigningKey = ExportedSessionKey ; MAC = HMAC-SHA256
# tronqué à 16 octets (MS-SMB2 §3.1.4.1).
#
# Pour SMB 3.x (AES-CMAC + KDF) : protocol/smb/smb3/signing.sh
#
# Dépendances : core/endian, core/log, crypto/hmac_sha256
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_SIGNING:-}" ]] && return 0
readonly _ENSH_SMB2_SIGNING=1

ensh::import core/endian
ensh::import core/log
ensh::import crypto/hmac_sha256

# smb2::signing::derive_key <var_out> <exported_session_key_hex> <dialect_int> [_ignored]
#
# Uniquement 0x0202 et 0x0210.
smb2::signing::derive_key() {
    local -n _smb2_sk_out="$1"
    local esk="${2^^}"
    local -i dialect="$3"

    if (( dialect == 0x0202 || dialect == 0x0210 )); then
        _smb2_sk_out="${esk}"
        log::debug "smb2::signing : clé directe (dialecte 2.0.2 / 2.1)"
        return 0
    fi

    log::error "smb2::signing::derive_key : dialecte 0x$(printf '%04X' "${dialect}") — utiliser smb3::signing pour SMB 3.x"
    return 1
}

# smb2::signing::sign <var_msg_inout> <signing_key_hex> <dialect_int>
smb2::signing::sign() {
    local -n _smb2_sign_msg="$1"
    local signing_key="${2^^}"
    local -i dialect="$3"
    local msg="${_smb2_sign_msg^^}"

    if [[ "${msg:0:8}" != "FE534D42" ]]; then
        log::error "smb2::signing::sign : en-tête SMB invalide"
        return 1
    fi

    if (( dialect != 0x0202 && dialect != 0x0210 )); then
        log::error "smb2::signing::sign : dialecte SMB 3.x — utiliser smb3::signing"
        return 1
    fi

    local -i _cur_flags; endian::read_le32 "${msg}" 16 _cur_flags
    local _new_flags_le; endian::le32 "$(( _cur_flags | 0x00000008 ))" _new_flags_le
    msg="${msg:0:32}${_new_flags_le}${msg:40}"

    msg="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    local mac
    hmac_sha256::compute "${signing_key}" "${msg}" mac || return 1

    msg="${msg:0:96}${mac:0:32}${msg:128}"

    _smb2_sign_msg="${msg}"
    log::debug "smb2::signing : signé (HMAC) — sig=${mac:0:16}..."
}

# smb2::signing::sign_nbt <var_nbt_msg_inout> <signing_key_hex> <dialect_int>
smb2::signing::sign_nbt() {
    local -n _smb2_snbt_msg="$1"
    local signing_key="$2"
    local -i dialect="$3"
    local nbt_msg="${_smb2_snbt_msg^^}"

    local nbt_hdr="${nbt_msg:0:8}"
    local smb2_payload="${nbt_msg:8}"

    smb2::signing::sign smb2_payload "${signing_key}" "${dialect}" || return 1

    _smb2_snbt_msg="${nbt_hdr}${smb2_payload}"
}

# smb2::signing::verify <msg_hex> <signing_key_hex> <dialect_int>
smb2::signing::verify() {
    local msg="${1^^}"
    local signing_key="${2^^}"
    local -i dialect="$3"

    if (( dialect != 0x0202 && dialect != 0x0210 )); then
        return 1
    fi

    local received_sig="${msg:96:32}"
    local msg_zeroed="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    local expected_mac
    hmac_sha256::compute "${signing_key}" "${msg_zeroed}" expected_mac || return 1

    local expected_sig="${expected_mac:0:32}"
    if [[ "${received_sig^^}" == "${expected_sig^^}" ]]; then
        return 0
    fi

    log::debug "smb2::signing::verify : ÉCHEC sig_reçue=${received_sig} attendue=${expected_sig}"
    return 1
}
