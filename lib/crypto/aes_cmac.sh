#!/usr/bin/env bash
#
# lib/crypto/aes_cmac.sh — AES-128-CMAC (RFC 4493)
#
# Calcule un AES-128-CMAC via openssl.
# Utilisé pour la signature SMB2 en dialecte >= 0x0300.
#
# Dépendances : core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_AES_CMAC:-}" ]] && return 0
readonly _ENSH_CRYPTO_AES_CMAC=1

ensh::import core/log

# aes_cmac::compute <key_hex> <data_hex> <var_out>
#
# Calcule AES-128-CMAC(key, data).
# <key_hex>  : clé AES-128 en hex (32 nibbles = 16 octets)
# <data_hex> : données en hexadécimal
# <var_out>  : reçoit le résultat en hexadécimal uppercase (16 octets = 32 nibbles)
aes_cmac::compute() {
    local key_hex="${1^^}"
    local data_hex="${2^^}"
    local -n _aes_cmac_out="$3"

    local result

    # Essai openssl 3.x (mac subcommand)
    result=$(
        printf '%s' "${data_hex}" \
            | xxd -r -p \
            | openssl mac \
                -macopt "hexkey:${key_hex}" \
                -macopt "cipher:aes-128-cbc" \
                CMAC 2>/dev/null \
            | tr -d '\n '
    )

    # Fallback openssl 1.x (dgst -mac cmac)
    if [[ -z "${result}" ]]; then
        result=$(
            printf '%s' "${data_hex}" \
                | xxd -r -p \
                | openssl dgst \
                    -mac cmac \
                    -macopt "hexkey:${key_hex}" \
                    -macopt "cipher:aes-128-cbc" \
                    -binary 2>/dev/null \
                | xxd -p \
                | tr -d '\n'
        )
    fi

    if [[ -z "${result}" ]]; then
        log::error "aes_cmac::compute : openssl a échoué (clé=${key_hex:0:8}...)"
        return 1
    fi

    # Certaines versions d'openssl préfixent "(stdin)= " — on garde seulement le hex
    result="${result##*= }"
    result="${result^^}"

    _aes_cmac_out="${result:0:32}"  # 16 octets
}
