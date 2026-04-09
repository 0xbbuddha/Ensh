#!/usr/bin/env bash
#
# lib/encoding/utf16.sh — Encodage UTF-16 Little-Endian
#
# Indispensable pour les protocoles Windows : NTLM, SMB et Kerberos encodent
# les chaînes en UTF-16LE (chaque caractère sur 2 octets, LSB en premier).
#
# Portée : ASCII et Latin-1 (U+0000 à U+00FF).
# Pour les caractères hors de cette plage, utiliser iconv si disponible.
#
# Dépendances : core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_ENCODING_UTF16:-}" ]] && return 0
readonly _ENSH_ENCODING_UTF16=1

ensh::import core/hex

# ── Encodage ──────────────────────────────────────────────────────────────────

# utf16::encode_le <string> <var_out>
#
# Encode une chaîne ASCII/Latin-1 en UTF-16LE hexadécimal.
#   utf16::encode_le "AB" out  → out="41004200"
utf16::encode_le() {
    local str="$1"
    local -n _utf16_el_out="$2"
    _utf16_el_out=""
    local -i i cp
    for (( i=0; i<${#str}; i++ )); do
        printf -v cp '%d' "'${str:${i}:1}"
        # UTF-16LE : octet bas d'abord, puis octet haut
        printf -v _utf16_el_out '%s%02X%02X' \
            "${_utf16_el_out}" \
            "$(( cp & 0xFF ))" \
            "$(( (cp >> 8) & 0xFF ))"
    done
}

# utf16::encode_be <string> <var_out>
#
# Encode une chaîne ASCII/Latin-1 en UTF-16BE hexadécimal.
#   utf16::encode_be "AB" out  → out="00410042"
utf16::encode_be() {
    local str="$1"
    local -n _utf16_eb_out="$2"
    _utf16_eb_out=""
    local -i i cp
    for (( i=0; i<${#str}; i++ )); do
        printf -v cp '%d' "'${str:${i}:1}"
        printf -v _utf16_eb_out '%s%02X%02X' \
            "${_utf16_eb_out}" \
            "$(( (cp >> 8) & 0xFF ))" \
            "$(( cp & 0xFF ))"
    done
}

# ── Décodage ─────────────────────────────────────────────────────────────────

# utf16::decode_le <hex> <var_out>
#
# Décode une chaîne UTF-16LE hexadécimale en ASCII/Latin-1.
# Les caractères hors U+007F sont représentés par '?' s'ils ne tiennent pas
# dans un octet Bash.
utf16::decode_le() {
    local hex="${1^^}"
    local -n _utf16_dl_out="$2"
    _utf16_dl_out=""
    local -i i lo hi cp
    for (( i=0; i<${#hex}; i+=4 )); do
        lo=$(( 16#${hex:${i}:2} ))
        hi=$(( 16#${hex:$(( i+2 )):2} ))
        cp=$(( (hi << 8) | lo ))
        if (( cp >= 32 && cp < 128 )); then
            printf -v _utf16_dl_out '%s%b' "${_utf16_dl_out}" "\\x$(printf '%02x' "${cp}")"
        elif (( cp == 0 )); then
            : # Ignorer les terminateurs nuls
        else
            _utf16_dl_out+='?'
        fi
    done
}

# utf16::decode_be <hex> <var_out>
#
# Décode une chaîne UTF-16BE hexadécimale en ASCII.
utf16::decode_be() {
    local hex="${1^^}"
    local -n _utf16_db_out="$2"
    _utf16_db_out=""
    local -i i hi lo cp
    for (( i=0; i<${#hex}; i+=4 )); do
        hi=$(( 16#${hex:${i}:2} ))
        lo=$(( 16#${hex:$(( i+2 )):2} ))
        cp=$(( (hi << 8) | lo ))
        if (( cp >= 32 && cp < 128 )); then
            printf -v _utf16_db_out '%s%b' "${_utf16_db_out}" "\\x$(printf '%02x' "${cp}")"
        elif (( cp == 0 )); then
            :
        else
            _utf16_db_out+='?'
        fi
    done
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# utf16::uppercase_le <hex_utf16le> <var_out>
#
# Met en majuscules une chaîne déjà encodée en UTF-16LE.
# Utilisé par NTLM pour la normalisation du nom de domaine.
utf16::uppercase_le() {
    local hex="${1^^}"
    local -n _utf16_up_out="$2"
    # Décoder, mettre en majuscules, ré-encoder
    local decoded
    utf16::decode_le "${hex}" decoded
    decoded="${decoded^^}"
    utf16::encode_le "${decoded}" _utf16_up_out
}
