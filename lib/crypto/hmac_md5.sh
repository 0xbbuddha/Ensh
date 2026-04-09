#!/usr/bin/env bash
#
# lib/crypto/hmac_md5.sh — HMAC-MD5 (RFC 2104)
#
# Utilisé dans NTLMv2 pour calculer NT-Proof-String et la réponse étendue.
# S'appuie sur `openssl` pour le MD5 brut (POSIX, disponible partout),
# avec un fallback Bash pur minimal.
#
# Référence : RFC 2104 (Krawczyk, 1997)
#
# Dépendances : core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_HMAC_MD5:-}" ]] && return 0
readonly _ENSH_CRYPTO_HMAC_MD5=1

ensh::import core/hex
ensh::import core/bytes

readonly _HMAC_MD5_BLOCK_SIZE=64   # 512 bits

# ── MD5 brut ──────────────────────────────────────────────────────────────────

# _hmac::md5_raw <hex_data> <var_out>
#
# Calcule le condensat MD5 de données hexadécimales.
# Utilise openssl dgst si disponible.
_hmac::md5_raw() {
    local hex="${1^^}"
    local -n _hmac_md5r_out="$2"

    if command -v openssl >/dev/null 2>&1; then
        _hmac_md5r_out="$(
            local i
            for (( i=0; i<${#hex}; i+=2 )); do
                printf "\\x${hex:${i}:2}"
            done | openssl dgst -md5 -binary | xxd -p | tr -d '\n'
        )"
        _hmac_md5r_out="${_hmac_md5r_out^^}"
        return 0
    fi

    # Pas d'openssl : erreur explicite
    log::die "hmac_md5 : openssl requis pour le calcul MD5"
}

# ── HMAC-MD5 ─────────────────────────────────────────────────────────────────

# hmac_md5::compute <hex_key> <hex_message> <var_out>
#
# Calcule HMAC-MD5(key, message).
# Entrées et sortie en hexadécimal.
hmac_md5::compute() {
    local key="${1^^}"
    local msg="${2^^}"
    local -n _hmac_out="$3"

    # Si la clé est plus longue que le bloc, on la hash
    if (( ${#key} / 2 > _HMAC_MD5_BLOCK_SIZE )); then
        _hmac::md5_raw "${key}" key
    fi

    # Padder la clé à la taille du bloc
    local key_padded
    hex::pad_right "${key}" "${_HMAC_MD5_BLOCK_SIZE}" key_padded

    # Construire les masques ipad (0x36 * blocksize) et opad (0x5C * blocksize)
    local ipad_mask opad_mask
    bytes::repeat "36" "${_HMAC_MD5_BLOCK_SIZE}" ipad_mask
    bytes::repeat "5C" "${_HMAC_MD5_BLOCK_SIZE}" opad_mask

    local k_ipad k_opad
    hex::xor "${key_padded}" "${ipad_mask}" k_ipad
    hex::xor "${key_padded}" "${opad_mask}" k_opad

    # HMAC = MD5(opad || MD5(ipad || message))
    local inner
    _hmac::md5_raw "${k_ipad}${msg}" inner
    _hmac::md5_raw "${k_opad}${inner}" _hmac_out
}

# hmac_md5::compute_str <key_string> <message_hex> <var_out>
#
# Raccourci : clé en ASCII, message en hex.
hmac_md5::compute_str() {
    local key_hex
    hex::from_string "$1" key_hex
    hmac_md5::compute "${key_hex}" "$2" "$3"
}
