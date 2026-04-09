#!/usr/bin/env bash
#
# lib/core/hex.sh — Manipulation de chaînes hexadécimales
#
# Convention Ensh : toutes les données binaires circulent sous forme de
# chaînes hexadécimales en majuscules, sans séparateur ni préfixe "0x".
# Exemple : "DEADBEEF", "0041004200"
#
# Dépendances : aucune (Bash pur)
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CORE_HEX:-}" ]] && return 0
readonly _ENSH_CORE_HEX=1

# ── Validation ────────────────────────────────────────────────────────────────

# hex::is_valid <hex>
# Retourne 0 si la chaîne est une suite valide de caractères hexadécimaux
# de longueur paire, 1 sinon.
hex::is_valid() {
    local hex="${1^^}"
    [[ $(( ${#hex} % 2 )) -eq 0 ]] && [[ "${hex}" =~ ^[0-9A-F]*$ ]]
}

# ── Conversion ────────────────────────────────────────────────────────────────

# hex::from_string <string> <var_out>
# Encode une chaîne ASCII en hexadécimal.
#   hex::from_string "AB" out  → out="4142"
hex::from_string() {
    local str="$1"
    local -n _hex_fs_out="$2"
    _hex_fs_out=""
    local i byte
    for (( i=0; i<${#str}; i++ )); do
        printf -v byte '%02X' "'${str:${i}:1}"
        _hex_fs_out+="${byte}"
    done
}

# hex::to_string <hex> <var_out>
# Décode une chaîne hexadécimale en ASCII.
# Les octets non imprimables sont conservés tels quels dans la variable.
hex::to_string() {
    local hex="${1^^}"
    local -n _hex_ts_out="$2"
    if [[ -z "${hex}" ]]; then
        _hex_ts_out=""
        return 0
    fi
    _hex_ts_out="$(printf '%b' "\\x${hex:0:2}$(
        local i
        for (( i=2; i<${#hex}; i+=2 )); do
            printf '\\x%s' "${hex:${i}:2}"
        done
    )")"
}

# hex::from_int <integer> <width_bytes> <var_out>
# Encode un entier en hexadécimal sur <width_bytes> octets (big-endian).
#   hex::from_int 256 2 out  → out="0100"
hex::from_int() {
    local -i value="$1"
    local -i width="$2"       # nombre d'octets
    local -n _hex_fi_out="$3"
    printf -v _hex_fi_out "%0$(( width * 2 ))X" "$(( value & ( (1 << (width*8)) - 1 ) ))"
}

# hex::to_int <hex> <var_out>
# Décode une chaîne hexadécimale (big-endian) en entier.
#   hex::to_int "0100" out  → out=256
hex::to_int() {
    local hex="${1^^}"
    local -n _hex_ti_out="$2"
    _hex_ti_out=$(( 16#${hex} ))
}

# ── Manipulation de chaînes hex ───────────────────────────────────────────────

# hex::concat <var_out> [hex...]
# Concatène plusieurs chaînes hexadécimales.
hex::concat() {
    local -n _hex_cat_out="$1"
    shift
    _hex_cat_out=""
    local part
    for part in "$@"; do
        _hex_cat_out+="${part^^}"
    done
}

# hex::slice <hex> <offset_bytes> <length_bytes> <var_out>
# Extrait une sous-séquence d'octets.
#   hex::slice "AABBCCDD" 1 2 out  → out="BBCC"
hex::slice() {
    local hex="${1^^}"
    local -i offset="$2"
    local -i length="$3"
    local -n _hex_sl_out="$4"
    _hex_sl_out="${hex:$(( offset * 2 )):$(( length * 2 ))}"
}

# hex::length <hex> <var_out>
# Retourne la longueur en octets d'une chaîne hexadécimale.
hex::length() {
    local hex="$1"
    local -n _hex_len_out="$2"
    _hex_len_out=$(( ${#hex} / 2 ))
}

# hex::pad_right <hex> <total_bytes> <var_out>
# Complète avec des zéros à droite jusqu'à atteindre <total_bytes> octets.
hex::pad_right() {
    local hex="${1^^}"
    local -i total="$2"
    local -n _hex_pr_out="$3"
    local -i current=$(( ${#hex} / 2 ))
    local padding=""
    if (( current < total )); then
        printf -v padding '%0*d' "$(( (total - current) * 2 ))" 0
    fi
    _hex_pr_out="${hex}${padding}"
}

# hex::pad_left <hex> <total_bytes> <var_out>
# Complète avec des zéros à gauche jusqu'à atteindre <total_bytes> octets.
hex::pad_left() {
    local hex="${1^^}"
    local -i total="$2"
    local -n _hex_pl_out="$3"
    local -i current=$(( ${#hex} / 2 ))
    local padding=""
    if (( current < total )); then
        printf -v padding '%0*d' "$(( (total - current) * 2 ))" 0
    fi
    _hex_pl_out="${padding}${hex}"
}

# hex::xor <hex_a> <hex_b> <var_out>
# XOR octet par octet de deux chaînes de même longueur.
hex::xor() {
    local a="${1^^}"
    local b="${2^^}"
    local -n _hex_xor_out="$3"
    _hex_xor_out=""
    local -i i len=$(( ${#a} / 2 ))
    for (( i=0; i<len; i++ )); do
        local ba=$(( 16#${a:$(( i*2 )):2} ))
        local bb=$(( 16#${b:$(( i*2 )):2} ))
        printf -v _hex_xor_out '%s%02X' "${_hex_xor_out}" "$(( ba ^ bb ))"
    done
}

# hex::to_bytes <hex> <var_out>
# Convertit une chaîne hex en tableau Bash d'entiers (un entier par octet).
hex::to_bytes() {
    local hex="${1^^}"
    local -n _hex_tb_out="$2"
    _hex_tb_out=()
    local i
    for (( i=0; i<${#hex}; i+=2 )); do
        _hex_tb_out+=( $(( 16#${hex:${i}:2} )) )
    done
}

# hex::from_bytes <var_out> [byte_int...]
# Construit une chaîne hex depuis un tableau d'entiers (0–255).
hex::from_bytes() {
    local -n _hex_fb_out="$1"
    shift
    _hex_fb_out=""
    local b
    for b in "$@"; do
        printf -v _hex_fb_out '%s%02X' "${_hex_fb_out}" "$(( b & 0xFF ))"
    done
}
