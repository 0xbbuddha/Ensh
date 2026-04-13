#!/usr/bin/env bash
#
# lib/crypto/hmac_sha256.sh — HMAC-SHA256
#
# Calcule un HMAC-SHA256 via openssl.
# Entrée/sortie : chaînes hexadécimales uppercase.
#
# Dépendances : core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_HMAC_SHA256:-}" ]] && return 0
readonly _ENSH_CRYPTO_HMAC_SHA256=1

ensh::import core/log

# hmac_sha256::compute <key_hex> <data_hex> <var_out>
#
# Calcule HMAC-SHA256(key, data).
# <key_hex>  : clé en hexadécimal (longueur quelconque)
# <data_hex> : données en hexadécimal
# <var_out>  : reçoit le résultat en hexadécimal uppercase (32 octets = 64 nibbles)
hmac_sha256::compute() {
    local key_hex="${1^^}"
    local data_hex="${2^^}"
    local -n _hmac256_out="$3"

    local result
    result=$(
        printf '%s' "${data_hex}" \
            | xxd -r -p \
            | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${key_hex}" -binary \
            | xxd -p \
            | tr -d '\n'
    )

    if [[ -z "${result}" ]]; then
        log::error "hmac_sha256::compute : openssl a échoué"
        return 1
    fi

    _hmac256_out="${result^^}"
}
