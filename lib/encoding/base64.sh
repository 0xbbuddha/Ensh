#!/usr/bin/env bash
#
# lib/encoding/base64.sh — Encodage et décodage Base64
#
# Implémentation Bash pure pour les environnements sans `base64` disponible.
# Si `base64` est présent, les fonctions s'appuient dessus pour la performance.
#
# Dépendances : core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_ENCODING_BASE64:-}" ]] && return 0
readonly _ENSH_ENCODING_BASE64=1

ensh::import core/hex

readonly _B64_TABLE='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# ── Encodage ──────────────────────────────────────────────────────────────────

# base64::encode_hex <hex> <var_out>
#
# Encode des données hexadécimales en Base64 standard (RFC 4648).
base64::encode_hex() {
    local hex="${1^^}"
    local -n _b64_eh_out="$2"

    # Préférer le binaire externe si disponible
    if command -v base64 >/dev/null 2>&1; then
        _b64_eh_out="$(
            local i
            for (( i=0; i<${#hex}; i+=2 )); do
                printf "\\x${hex:${i}:2}"
            done | base64 | tr -d '\n'
        )"
        return 0
    fi

    # Implémentation Bash pure
    local -i i=0 b0 b1 b2 triplet len
    len=$(( ${#hex} / 2 ))
    _b64_eh_out=""

    while (( i < len )); do
        b0=$(( 16#${hex:$(( i*2 )):2} ))
        b1=0; b2=0
        (( i+1 < len )) && b1=$(( 16#${hex:$(( (i+1)*2 )):2} ))
        (( i+2 < len )) && b2=$(( 16#${hex:$(( (i+2)*2 )):2} ))

        triplet=$(( (b0 << 16) | (b1 << 8) | b2 ))

        _b64_eh_out+="${_B64_TABLE:$(( (triplet >> 18) & 63 )):1}"
        _b64_eh_out+="${_B64_TABLE:$(( (triplet >> 12) & 63 )):1}"

        if (( i+1 < len )); then
            _b64_eh_out+="${_B64_TABLE:$(( (triplet >> 6) & 63 )):1}"
        else
            _b64_eh_out+='='
        fi

        if (( i+2 < len )); then
            _b64_eh_out+="${_B64_TABLE:$(( triplet & 63 )):1}"
        else
            _b64_eh_out+='='
        fi

        (( i += 3 ))
    done
}

# base64::encode_string <string> <var_out>
#
# Encode une chaîne ASCII en Base64.
base64::encode_string() {
    local str="$1"
    local hex
    hex::from_string "${str}" hex
    base64::encode_hex "${hex}" "$2"
}

# ── Décodage ─────────────────────────────────────────────────────────────────

# base64::decode <b64_string> <var_hex_out>
#
# Décode une chaîne Base64 en hexadécimal.
base64::decode() {
    local b64="$1"
    local -n _b64_dec_out="$2"

    if command -v base64 >/dev/null 2>&1; then
        local raw
        raw="$(printf '%s' "${b64}" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')"
        _b64_dec_out="${raw^^}"
        return 0
    fi

    # Table de décodage inverse
    local -A _B64_REV=()
    local -i k
    for (( k=0; k<64; k++ )); do
        _B64_REV["${_B64_TABLE:${k}:1}"]="${k}"
    done

    # Retirer le padding et les espaces
    b64="${b64//[[:space:]]/}"
    b64="${b64//=/}"

    _b64_dec_out=""
    local -i i=0 len="${#b64}" v0 v1 v2 v3

    while (( i < len )); do
        v0="${_B64_REV[${b64:${i}:1}]:-0}"
        v1="${_B64_REV[${b64:$(( i+1 )):1}]:-0}"
        v2="${_B64_REV[${b64:$(( i+2 )):1}]:-0}"
        v3="${_B64_REV[${b64:$(( i+3 )):1}]:-0}"

        printf -v _b64_dec_out '%s%02X' "${_b64_dec_out}" "$(( (v0 << 2) | (v1 >> 4) ))"

        if (( i+2 < len )); then
            printf -v _b64_dec_out '%s%02X' "${_b64_dec_out}" "$(( ((v1 & 0xF) << 4) | (v2 >> 2) ))"
        fi
        if (( i+3 < len )); then
            printf -v _b64_dec_out '%s%02X' "${_b64_dec_out}" "$(( ((v2 & 0x3) << 6) | v3 ))"
        fi

        (( i += 4 ))
    done
}
