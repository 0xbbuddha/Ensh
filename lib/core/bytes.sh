#!/usr/bin/env bash
#
# lib/core/bytes.sh — Opérations sur des buffers d'octets (hex strings)
#
# Ce module fournit les primitives pour construire et analyser des messages
# réseau : buffers, champs de longueur, structures à décalage fixe.
#
# Convention : un "buffer" est une variable contenant une chaîne hex.
# Les fonctions qui modifient un buffer le font via une nameref ("-n").
#
# Dépendances : core/hex, core/endian
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CORE_BYTES:-}" ]] && return 0
readonly _ENSH_CORE_BYTES=1

ensh::import core/hex
ensh::import core/endian

# ── Construction de buffers ───────────────────────────────────────────────────

# bytes::new <var_out>
# Initialise un buffer vide.
bytes::new() {
    local -n _bytes_new_out="$1"
    _bytes_new_out=""
}

# bytes::append <var_buf> <hex_data>
# Ajoute des données hex à la fin d'un buffer.
bytes::append() {
    local -n _bytes_ap_buf="$1"
    _bytes_ap_buf+="${2^^}"
}

# bytes::prepend <var_buf> <hex_data>
# Insère des données hex au début d'un buffer.
bytes::prepend() {
    local -n _bytes_pp_buf="$1"
    _bytes_pp_buf="${2^^}${_bytes_pp_buf}"
}

# bytes::write_at <var_buf> <offset_bytes> <hex_data>
# Écrase <len(hex_data)> octets à partir de <offset_bytes> dans le buffer.
bytes::write_at() {
    local -n _bytes_wa_buf="$1"
    local -i off="$2"
    local data="${3^^}"
    local before="${_bytes_wa_buf:0:$(( off * 2 ))}"
    local after="${_bytes_wa_buf:$(( (off * 2) + ${#data} ))}"
    _bytes_wa_buf="${before}${data}${after}"
}

# ── Lecture dans un buffer ────────────────────────────────────────────────────

# bytes::read <hex_buf> <offset_bytes> <length_bytes> <var_out>
# Extrait <length_bytes> octets depuis <offset_bytes>.
bytes::read() {
    hex::slice "$1" "$2" "$3" "$4"
}

# bytes::read_u8 <hex_buf> <offset> <var_out>
bytes::read_u8() {
    local -n _bytes_ru8_out="$3"
    _bytes_ru8_out=$(( 16#${1:$(( $2 * 2 )):2} ))
}

# bytes::read_le16 <hex_buf> <offset> <var_out>
bytes::read_le16() { endian::read_le16 "$1" "$2" "$3"; }

# bytes::read_le32 <hex_buf> <offset> <var_out>
bytes::read_le32() { endian::read_le32 "$1" "$2" "$3"; }

# bytes::read_be16 <hex_buf> <offset> <var_out>
bytes::read_be16() { endian::read_be16 "$1" "$2" "$3"; }

# bytes::read_be32 <hex_buf> <offset> <var_out>
bytes::read_be32() { endian::read_be32 "$1" "$2" "$3"; }

# ── Sérialisation de champs courants ──────────────────────────────────────────

# bytes::field_u8 <uint8> <var_out>
bytes::field_u8() { endian::le8 "$1" "$2"; }

# bytes::field_le16 <uint16> <var_out>
bytes::field_le16() { endian::le16 "$1" "$2"; }

# bytes::field_le32 <uint32> <var_out>
bytes::field_le32() { endian::le32 "$1" "$2"; }

# bytes::field_be16 <uint16> <var_out>
bytes::field_be16() { endian::be16 "$1" "$2"; }

# bytes::field_be32 <uint32> <var_out>
bytes::field_be32() { endian::be32 "$1" "$2"; }

# ── Utilitaires ───────────────────────────────────────────────────────────────

# bytes::size <hex_buf> <var_out>
# Retourne la taille en octets du buffer.
bytes::size() {
    local -n _bytes_sz_out="$2"
    _bytes_sz_out=$(( ${#1} / 2 ))
}

# bytes::zero <count> <var_out>
# Génère <count> octets nuls (00).
bytes::zero() {
    local -i count="$1"
    local -n _bytes_z_out="$2"
    if (( count == 0 )); then
        _bytes_z_out=""
        return 0
    fi
    printf -v _bytes_z_out '%0*d' "$(( count * 2 ))" 0
}

# bytes::repeat <hex_byte> <count> <var_out>
# Répète un octet hex <count> fois.
#   bytes::repeat "FF" 4 out  → out="FFFFFFFF"
bytes::repeat() {
    local byte="${1^^}"
    local -i count="$2"
    local -n _bytes_rep_out="$3"
    _bytes_rep_out=""
    local -i i
    for (( i=0; i<count; i++ )); do
        _bytes_rep_out+="${byte}"
    done
}

# bytes::to_raw <hex_buf> <var_out>
# Convertit une chaîne hex en données binaires brutes dans une variable Bash.
# Attention : les octets nuls sont tronqués par Bash.
bytes::to_raw() {
    local hex="${1^^}"
    local -n _bytes_tr_out="$2"
    _bytes_tr_out="$(printf '%b' "$(
        local i
        for (( i=0; i<${#hex}; i+=2 )); do
            printf '\\x%s' "${hex:${i}:2}"
        done
    )")"
}

# bytes::from_raw <raw_string> <var_out>
# Convertit des données binaires brutes en hex.
# Limité aux caractères non-nuls du fait des contraintes de Bash.
bytes::from_raw() {
    local raw="$1"
    local -n _bytes_fr_out="$2"
    _bytes_fr_out=""
    local i
    for (( i=0; i<${#raw}; i++ )); do
        printf -v _bytes_fr_out '%s%02X' "${_bytes_fr_out}" "'${raw:${i}:1}"
    done
}
