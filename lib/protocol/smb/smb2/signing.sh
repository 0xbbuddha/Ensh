#!/usr/bin/env bash
#
# lib/protocol/smb/smb2/signing.sh — Signature des messages SMB2
#
# Implémente la dérivation de la clé de signature et la signature des messages
# SMB2 conformément à MS-SMB2 §3.1.4.1 et §3.2.5.3.
#
# Dialectes supportés :
#   0x0202, 0x0210 (SMB 2.x) → HMAC-SHA256(SigningKey, message)
#   0x0300, 0x0302, 0x0311 (SMB 3.x) → AES-128-CMAC(SigningKey, message)
#
# Dérivation de la SigningKey (MS-SMB2 §3.2.5.3) :
#   SMB 2.x : SigningKey = ExportedSessionKey (direct)
#   SMB 3.x : SigningKey = SP800_108_KDF(ExportedSessionKey,
#                               "SMBSigningKey\0", SessionId, 128 bits)
#
# SP800-108 CTR Mode (MS-SMB2 §3.1.4.2) :
#   KDF(K_I, Label, Context, L=128) :
#     T1 = HMAC-SHA256(K_I, 0x00000001 || Label || 0x00 || Context || L_BE32)
#     return first 16 bytes of T1
#
# Signature d'un message :
#   1. Mettre SMB2_FLAGS_SIGNED dans le header (offset 16, LE32)
#   2. Mettre à zéro le champ Signature (offset 48, 16 octets)
#   3. Calculer MAC sur le message entier
#   4. Écrire les 16 premiers octets du MAC dans le champ Signature
#
# Dépendances : core/endian, core/log, crypto/hmac_sha256, crypto/aes_cmac
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB2_SIGNING:-}" ]] && return 0
readonly _ENSH_SMB2_SIGNING=1

ensh::import core/endian
ensh::import core/log
ensh::import crypto/hmac_sha256
ensh::import crypto/aes_cmac

# ── Constantes ────────────────────────────────────────────────────────────────

# KDF labels (MS-SMB2 §3.2.5.3)
readonly _SMB2_KDF_LABEL_SIGNING="534D425369676E696E674B657900"  # "SMBSigningKey\0"

# ── Dérivation de la SigningKey ───────────────────────────────────────────────

# smb2::signing::derive_key <var_out> <exported_session_key_hex>
#                           <dialect_int> <session_id_hex16>
#
# Dérive la clé de signature à partir de l'ExportedSessionKey NTLM.
# <session_id_hex16> : SessionId tel que stocké dans le registre SMB (8 octets LE hex)
smb2::signing::derive_key() {
    local -n _smb2_sk_out="$1"
    local esk="${2^^}"
    local -i dialect="$3"
    local session_id="${4^^}"

    if (( dialect <= 0x0210 )); then
        # SMB 2.x : SigningKey = ExportedSessionKey directement
        _smb2_sk_out="${esk}"
        log::debug "smb2::signing : clé directe (dialecte 2.x)"
        return 0
    fi

    # SMB 3.x : SP800-108 KDF
    # KDF(K_I, Label, Context, L=128) :
    #   input = 0x00000001 || Label || 0x00 || Context || 0x00000080
    #
    # Label = "SMBSigningKey\0" = 534D425369676E696E674B657900 (14 octets)
    # Context = SessionId (8 octets LE, tel que reçu)
    # L = 128 = 0x00000080

    local kdf_input=""
    kdf_input+="00000001"                     # counter i=1 (BE32)
    kdf_input+="${_SMB2_KDF_LABEL_SIGNING}"   # "SMBSigningKey\0"
    kdf_input+="00"                           # séparateur 0x00
    kdf_input+="${session_id}"                # Context = SessionId (8 octets)
    kdf_input+="00000080"                     # L = 128 bits (BE32)

    local kdf_result
    hmac_sha256::compute "${esk}" "${kdf_input}" kdf_result || return 1

    # Prendre les 16 premiers octets (128 bits)
    _smb2_sk_out="${kdf_result:0:32}"
    log::debug "smb2::signing : SigningKey dérivée (dialecte 3.x) = ${_smb2_sk_out}"
}

# ── Signature d'un message ────────────────────────────────────────────────────

# smb2::signing::sign <var_msg_inout> <signing_key_hex> <dialect_int>
#
# Signe un message SMB2 brut (SANS wrapper NBT).
# Modifie le message en place :
#   - Positionne SMB2_FLAGS_SIGNED dans les Flags
#   - Calcule et insère la Signature (offset 48, 16 octets)
smb2::signing::sign() {
    local -n _smb2_sign_msg="$1"
    local signing_key="${2^^}"
    local -i dialect="$3"
    local msg="${_smb2_sign_msg^^}"

    # Vérifier la signature SMB2
    if [[ "${msg:0:8}" != "FE534D42" ]]; then
        log::error "smb2::signing::sign : ce n'est pas un message SMB2"
        return 1
    fi

    # 1. Positionner SMB2_FLAGS_SIGNED (0x00000008) dans les Flags (offset 16, LE32)
    local -i _cur_flags; endian::read_le32 "${msg}" 16 _cur_flags
    local _new_flags_le; endian::le32 "$(( _cur_flags | 0x00000008 ))" _new_flags_le
    # Remplacer les nibbles 32-39 (offset 16 * 2 = 32)
    msg="${msg:0:32}${_new_flags_le}${msg:40}"

    # 2. Mettre à zéro la Signature (offset 48, 16 octets = 32 nibbles)
    #    nibbles 96-127
    msg="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    # 3. Calculer le MAC
    local mac
    if (( dialect <= 0x0210 )); then
        hmac_sha256::compute "${signing_key}" "${msg}" mac || return 1
    else
        aes_cmac::compute "${signing_key}" "${msg}" mac || return 1
    fi

    # 4. Inscrire les 16 premiers octets du MAC dans la Signature
    msg="${msg:0:96}${mac:0:32}${msg:128}"

    _smb2_sign_msg="${msg}"
    log::debug "smb2::signing : signé — sig=${mac:0:16}..."
}

# smb2::signing::sign_nbt <var_nbt_msg_inout> <signing_key_hex> <dialect_int>
#
# Signe un message SMB2 encapsulé dans un wrapper NBT (4 octets).
# Extrait le payload SMB2, le signe, puis reconstruit l'enveloppe NBT.
smb2::signing::sign_nbt() {
    local -n _smb2_snbt_msg="$1"
    local signing_key="$2"
    local -i dialect="$3"
    local nbt_msg="${_smb2_snbt_msg^^}"

    # Le wrapper NBT fait 4 octets = 8 nibbles
    local nbt_hdr="${nbt_msg:0:8}"
    local smb2_payload="${nbt_msg:8}"

    # Signer le payload SMB2
    smb2::signing::sign smb2_payload "${signing_key}" "${dialect}" || return 1

    # Reconstruire avec le même header NBT (la taille ne change pas)
    _smb2_snbt_msg="${nbt_hdr}${smb2_payload}"
}

# smb2::signing::verify <msg_hex> <signing_key_hex> <dialect_int> → retcode
#
# Vérifie la signature d'un message SMB2 brut (sans NBT).
# Retourne 0 si la signature est valide, 1 sinon.
smb2::signing::verify() {
    local msg="${1^^}"
    local signing_key="${2^^}"
    local -i dialect="$3"

    # Extraire la signature reçue (offset 48, 16 octets)
    local received_sig="${msg:96:32}"

    # Zéroïser la signature pour recalcul
    local msg_zeroed="${msg:0:96}$(printf '%032d' 0)${msg:128}"

    local expected_mac
    if (( dialect <= 0x0210 )); then
        hmac_sha256::compute "${signing_key}" "${msg_zeroed}" expected_mac || return 1
    else
        aes_cmac::compute "${signing_key}" "${msg_zeroed}" expected_mac || return 1
    fi

    local expected_sig="${expected_mac:0:32}"
    if [[ "${received_sig^^}" == "${expected_sig^^}" ]]; then
        return 0
    fi

    log::debug "smb2::signing::verify : ÉCHEC sig_reçue=${received_sig} attendue=${expected_sig}"
    return 1
}
