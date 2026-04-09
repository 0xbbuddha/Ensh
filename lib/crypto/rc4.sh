#!/usr/bin/env bash
#
# lib/crypto/rc4.sh — Chiffrement RC4 / ARCFOUR (RFC 4757)
#
# RC4 est utilisé dans NTLMv1 et les sessions SMB signées (mode "sealed").
# Algorithme : initialisation du S-box (KSA), puis génération du keystream (PRGA).
#
# Performances : l'implémentation Bash pure est lente sur de grands volumes.
# Pour des données > 1 Ko, préférer openssl rc4 si disponible.
#
# Dépendances : core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_RC4:-}" ]] && return 0
readonly _ENSH_CRYPTO_RC4=1

ensh::import core/hex

# ── Implémentation Bash pure ──────────────────────────────────────────────────

# rc4::crypt <hex_key> <hex_data> <var_out>
#
# Chiffre ou déchiffre des données avec RC4 (symétrique).
# Entrées et sortie en hexadécimal.
rc4::crypt() {
    local key="${1^^}"
    local data="${2^^}"
    local -n _rc4_out="$3"

    local -i klen=$(( ${#key} / 2 ))
    local -i dlen=$(( ${#data} / 2 ))

    # Détecter openssl pour accélérer les gros volumes
    if (( dlen > 1024 )) && command -v openssl >/dev/null 2>&1; then
        rc4::crypt_openssl "${key}" "${data}" _rc4_out
        return $?
    fi

    # ── KSA (Key Scheduling Algorithm) ────────────────────────────────────────
    local -a S=()
    local -i i
    for (( i=0; i<256; i++ )); do S[${i}]="${i}"; done

    local -i j=0
    for (( i=0; i<256; i++ )); do
        local ki=$(( 16#${key:$(( (i % klen) * 2 )):2} ))
        j=$(( (j + S[i] + ki) % 256 ))
        local tmp="${S[${i}]}"
        S[${i}]="${S[${j}]}"
        S[${j}]="${tmp}"
    done

    # ── PRGA (Pseudo-Random Generation Algorithm) ─────────────────────────────
    _rc4_out=""
    i=0; j=0
    local -i k
    for (( k=0; k<dlen; k++ )); do
        i=$(( (i + 1) % 256 ))
        j=$(( (j + S[i]) % 256 ))
        local tmp="${S[${i}]}"
        S[${i}]="${S[${j}]}"
        S[${j}]="${tmp}"
        local ks=$(( S[(S[i] + S[j]) % 256] ))
        local db=$(( 16#${data:$(( k*2 )):2} ))
        printf -v _rc4_out '%s%02X' "${_rc4_out}" "$(( db ^ ks ))"
    done
}

# rc4::crypt_openssl <hex_key> <hex_data> <var_out>
#
# Version accélérée via openssl (utilisée automatiquement pour les grands volumes).
rc4::crypt_openssl() {
    local key="${1^^}"
    local data="${2^^}"
    local -n _rc4_ossl_out="$3"

    _rc4_ossl_out="$(
        local i
        for (( i=0; i<${#data}; i+=2 )); do
            printf "\\x${data:${i}:2}"
        done | openssl enc -rc4 -nosalt -K "${key}" 2>/dev/null | xxd -p | tr -d '\n'
    )"
    _rc4_ossl_out="${_rc4_ossl_out^^}"
}
