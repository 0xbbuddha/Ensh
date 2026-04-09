#!/usr/bin/env bash
#
# lib/core/endian.sh — Conversions little-endian / big-endian
#
# Les protocoles Windows (SMB, NTLM…) utilisent massivement le little-endian.
# Ce module fournit des fonctions explicites pour convertir des entiers en
# représentation hexadécimale dans l'endianness souhaitée.
#
# Convention : toutes les fonctions retournent des chaînes hex en majuscules.
#
# Dépendances : core/hex
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CORE_ENDIAN:-}" ]] && return 0
readonly _ENSH_CORE_ENDIAN=1

ensh::import core/hex

# ── Big-endian ────────────────────────────────────────────────────────────────

# endian::be8 <uint8> <var_out>
endian::be8() {
    local -n _end_be8_out="$2"
    printf -v _end_be8_out '%02X' "$(( $1 & 0xFF ))"
}

# endian::be16 <uint16> <var_out>
endian::be16() {
    local -n _end_be16_out="$2"
    printf -v _end_be16_out '%04X' "$(( $1 & 0xFFFF ))"
}

# endian::be32 <uint32> <var_out>
endian::be32() {
    local -n _end_be32_out="$2"
    printf -v _end_be32_out '%08X' "$(( $1 & 0xFFFFFFFF ))"
}

# endian::be64 <uint64> <var_out>
endian::be64() {
    local -n _end_be64_out="$2"
    printf -v _end_be64_out '%016X' "$1"
}

# ── Little-endian ─────────────────────────────────────────────────────────────
#
# Le little-endian stocke l'octet de poids faible en premier.
# Exemple : 0x1234 en LE16 → "3412"

# endian::le8 <uint8> <var_out>
# (identique au BE8, fourni pour la symétrie)
endian::le8() {
    local -n _end_le8_out="$2"
    printf -v _end_le8_out '%02X' "$(( $1 & 0xFF ))"
}

# endian::le16 <uint16> <var_out>
endian::le16() {
    local v=$(( $1 & 0xFFFF ))
    local -n _end_le16_out="$2"
    printf -v _end_le16_out '%02X%02X' \
        "$(( v & 0xFF ))" \
        "$(( (v >> 8) & 0xFF ))"
}

# endian::le32 <uint32> <var_out>
endian::le32() {
    local v=$(( $1 & 0xFFFFFFFF ))
    local -n _end_le32_out="$2"
    printf -v _end_le32_out '%02X%02X%02X%02X' \
        "$(( v & 0xFF ))"         \
        "$(( (v >>  8) & 0xFF ))" \
        "$(( (v >> 16) & 0xFF ))" \
        "$(( (v >> 24) & 0xFF ))"
}

# endian::le64 <uint64_hi> <uint64_lo> <var_out>
# Bash ne gère pas les entiers 64 bits non signés nativement.
# On passe la valeur en deux moitiés 32 bits (hi = bits 63..32, lo = bits 31..0).
endian::le64() {
    local hi=$(( $1 & 0xFFFFFFFF ))
    local lo=$(( $2 & 0xFFFFFFFF ))
    local -n _end_le64_out="$3"
    printf -v _end_le64_out '%02X%02X%02X%02X%02X%02X%02X%02X' \
        "$(( lo & 0xFF ))"         \
        "$(( (lo >>  8) & 0xFF ))" \
        "$(( (lo >> 16) & 0xFF ))" \
        "$(( (lo >> 24) & 0xFF ))" \
        "$(( hi & 0xFF ))"         \
        "$(( (hi >>  8) & 0xFF ))" \
        "$(( (hi >> 16) & 0xFF ))" \
        "$(( (hi >> 24) & 0xFF ))"
}

# ── Lecture depuis un champ hex ───────────────────────────────────────────────

# endian::read_le16 <hex> <byte_offset> <var_out>
# Lit 2 octets à <byte_offset> dans la chaîne hex et les interprète en LE.
endian::read_le16() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _end_rle16_out="$3"
    local lo=$(( 16#${hex:$(( off*2 )):2} ))
    local hi=$(( 16#${hex:$(( off*2+2 )):2} ))
    _end_rle16_out=$(( (hi << 8) | lo ))
}

# endian::read_le32 <hex> <byte_offset> <var_out>
# Lit 4 octets à <byte_offset> et les interprète en LE.
endian::read_le32() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _end_rle32_out="$3"
    local b0=$(( 16#${hex:$(( off*2    )):2} ))
    local b1=$(( 16#${hex:$(( off*2+2  )):2} ))
    local b2=$(( 16#${hex:$(( off*2+4  )):2} ))
    local b3=$(( 16#${hex:$(( off*2+6  )):2} ))
    _end_rle32_out=$(( b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) ))
}

# endian::read_be16 <hex> <byte_offset> <var_out>
endian::read_be16() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _end_rbe16_out="$3"
    _end_rbe16_out=$(( 16#${hex:$(( off*2 )):4} ))
}

# endian::read_be32 <hex> <byte_offset> <var_out>
endian::read_be32() {
    local hex="${1^^}"
    local -i off="$2"
    local -n _end_rbe32_out="$3"
    _end_rbe32_out=$(( 16#${hex:$(( off*2 )):8} ))
}

# ── Inversion ─────────────────────────────────────────────────────────────────

# endian::swap <hex> <var_out>
# Inverse l'ordre des octets d'une chaîne hex (LE ↔ BE).
#   endian::swap "01020304" out  → out="04030201"
endian::swap() {
    local hex="${1^^}"
    local -n _end_sw_out="$2"
    _end_sw_out=""
    local -i i
    for (( i=${#hex}-2; i>=0; i-=2 )); do
        _end_sw_out+="${hex:${i}:2}"
    done
}
