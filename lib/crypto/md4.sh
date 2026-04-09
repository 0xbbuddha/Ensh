#!/usr/bin/env bash
#
# lib/crypto/md4.sh — Algorithme de hachage MD4 (RFC 1320)
#
# MD4 est utilisé pour calculer le NT hash d'un mot de passe Windows.
# C'est un algorithme obsolète du point de vue de la sécurité, mais
# nécessaire pour interopérer avec l'authentification NTLM.
#
# Référence : RFC 1320 (Rivest, 1992)
#
# Implémentation Bash pure — sans dépendance externe.
# Note : Bash ne gère que des entiers signés 64 bits. Les opérations 32 bits
# sont masquées avec & 0xFFFFFFFF pour simuler le dépassement.
#
# Dépendances : core/hex, core/endian
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_MD4:-}" ]] && return 0
readonly _ENSH_CRYPTO_MD4=1

ensh::import core/hex
ensh::import core/endian

# ── Opérations 32 bits avec masque ───────────────────────────────────────────

_md4::add32() {
    echo $(( ($1 + $2) & 0xFFFFFFFF ))
}

_md4::rol32() {
    local -i v="$1" s="$2"
    echo $(( ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF ))
}

# ── Fonctions auxiliaires MD4 ─────────────────────────────────────────────────

_md4::F() { echo $(( ($1 & $2) | (~$1 & $3) & 0xFFFFFFFF )); }
_md4::G() { echo $(( ($1 & $2) | ($1 & $3) | ($2 & $3) )); }
_md4::H() { echo $(( ($1 ^ $2 ^ $3) )); }

# ── Padding du message (RFC 1320 §3.1) ───────────────────────────────────────

# _md4::pad <hex_message> <var_out>
#
# Applique le padding MD4 :
#  1. Ajouter le bit 1 (octet 0x80)
#  2. Compléter avec des 0 jusqu'à 448 bits mod 512
#  3. Ajouter la longueur originale en bits sur 64 bits LE
_md4::pad() {
    local msg="${1^^}"
    local -n _md4_pad_out="$2"

    local -i bit_len=$(( ${#msg} * 4 ))   # longueur en bits (4 bits par nibble)
    local -i byte_len=$(( ${#msg} / 2 ))

    # 1. Bit 1 → octet 0x80
    msg+="80"

    # 2. Zéros jusqu'à 56 octets mod 64 (448 bits mod 512)
    local -i current_bytes=$(( ${#msg} / 2 ))
    local -i pad_bytes=$(( (56 - current_bytes % 64 + 64) % 64 ))
    local zeros
    printf -v zeros '%0*d' "$(( pad_bytes * 2 ))" 0
    msg+="${zeros}"

    # 3. Longueur originale en bits sur 64 bits LE
    local len_lo=$(( bit_len & 0xFFFFFFFF ))
    local len_hi=$(( (bit_len >> 32) & 0xFFFFFFFF ))
    local len_hex
    endian::le64 "${len_hi}" "${len_lo}" len_hex
    msg+="${len_hex}"

    _md4_pad_out="${msg}"
}

# ── Calcul du condensat ───────────────────────────────────────────────────────

# md4::hash <hex_message> <var_out>
#
# Calcule le condensat MD4 d'un message donné en hexadécimal.
# Le résultat est une chaîne hex de 32 caractères (16 octets).
md4::hash() {
    local msg="${1^^}"
    local -n _md4_hash_out="$2"

    local padded
    _md4::pad "${msg}" padded

    # Constantes de la norme
    local -i A=0x67452301
    local -i B=0xEFCDAB89
    local -i C=0x98BADCFE
    local -i D=0x10325476

    # Traitement par blocs de 512 bits (64 octets = 128 nibbles)
    local -i block_count=$(( ${#padded} / 128 ))
    local -i blk

    for (( blk=0; blk<block_count; blk++ )); do
        local block="${padded:$(( blk * 128 )):128}"

        # Charger les 16 mots de 32 bits en little-endian
        local -a X=()
        local -i j
        for (( j=0; j<16; j++ )); do
            endian::read_le32 "${block}" "$(( j * 4 ))" X[${j}]
        done

        local -i AA="${A}" BB="${B}" CC="${C}" DD="${D}"

        # ── Round 1 ────────────────────────────────────────────────────────────
        local -a R1_K=( 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 )
        local -a R1_S=( 3 7 11 19 3 7 11 19 3 7 11 19 3 7 11 19 )
        local -i i
        for (( i=0; i<16; i++ )); do
            local -i f
            case $(( i % 4 )) in
                0) A=$(( A + $(_md4::F "${B}" "${C}" "${D}") + ${X[${R1_K[${i}]}]} )); A=$(( A & 0xFFFFFFFF )); A=$(_md4::rol32 "${A}" "${R1_S[${i}]}") ;;
                1) D=$(( D + $(_md4::F "${A}" "${B}" "${C}") + ${X[${R1_K[${i}]}]} )); D=$(( D & 0xFFFFFFFF )); D=$(_md4::rol32 "${D}" "${R1_S[${i}]}") ;;
                2) C=$(( C + $(_md4::F "${D}" "${A}" "${B}") + ${X[${R1_K[${i}]}]} )); C=$(( C & 0xFFFFFFFF )); C=$(_md4::rol32 "${C}" "${R1_S[${i}]}") ;;
                3) B=$(( B + $(_md4::F "${C}" "${D}" "${A}") + ${X[${R1_K[${i}]}]} )); B=$(( B & 0xFFFFFFFF )); B=$(_md4::rol32 "${B}" "${R1_S[${i}]}") ;;
            esac
        done

        # ── Round 2 ────────────────────────────────────────────────────────────
        local -a R2_K=( 0 4 8 12 1 5 9 13 2 6 10 14 3 7 11 15 )
        local -a R2_S=( 3 5 9 13 3 5 9 13 3 5 9 13 3 5 9 13 )
        local -i C2=0x5A827999
        for (( i=0; i<16; i++ )); do
            case $(( i % 4 )) in
                0) A=$(( A + $(_md4::G "${B}" "${C}" "${D}") + ${X[${R2_K[${i}]}]} + C2 )); A=$(( A & 0xFFFFFFFF )); A=$(_md4::rol32 "${A}" "${R2_S[${i}]}") ;;
                1) D=$(( D + $(_md4::G "${A}" "${B}" "${C}") + ${X[${R2_K[${i}]}]} + C2 )); D=$(( D & 0xFFFFFFFF )); D=$(_md4::rol32 "${D}" "${R2_S[${i}]}") ;;
                2) C=$(( C + $(_md4::G "${D}" "${A}" "${B}") + ${X[${R2_K[${i}]}]} + C2 )); C=$(( C & 0xFFFFFFFF )); C=$(_md4::rol32 "${C}" "${R2_S[${i}]}") ;;
                3) B=$(( B + $(_md4::G "${C}" "${D}" "${A}") + ${X[${R2_K[${i}]}]} + C2 )); B=$(( B & 0xFFFFFFFF )); B=$(_md4::rol32 "${B}" "${R2_S[${i}]}") ;;
            esac
        done

        # ── Round 3 ────────────────────────────────────────────────────────────
        local -a R3_K=( 0 8 4 12 2 10 6 14 1 9 5 13 3 11 7 15 )
        local -a R3_S=( 3 9 11 15 3 9 11 15 3 9 11 15 3 9 11 15 )
        local -i C3=0x6ED9EBA1
        for (( i=0; i<16; i++ )); do
            case $(( i % 4 )) in
                0) A=$(( A + $(_md4::H "${B}" "${C}" "${D}") + ${X[${R3_K[${i}]}]} + C3 )); A=$(( A & 0xFFFFFFFF )); A=$(_md4::rol32 "${A}" "${R3_S[${i}]}") ;;
                1) D=$(( D + $(_md4::H "${A}" "${B}" "${C}") + ${X[${R3_K[${i}]}]} + C3 )); D=$(( D & 0xFFFFFFFF )); D=$(_md4::rol32 "${D}" "${R3_S[${i}]}") ;;
                2) C=$(( C + $(_md4::H "${D}" "${A}" "${B}") + ${X[${R3_K[${i}]}]} + C3 )); C=$(( C & 0xFFFFFFFF )); C=$(_md4::rol32 "${C}" "${R3_S[${i}]}") ;;
                3) B=$(( B + $(_md4::H "${C}" "${D}" "${A}") + ${X[${R3_K[${i}]}]} + C3 )); B=$(( B & 0xFFFFFFFF )); B=$(_md4::rol32 "${B}" "${R3_S[${i}]}") ;;
            esac
        done

        A=$(( (A + AA) & 0xFFFFFFFF ))
        B=$(( (B + BB) & 0xFFFFFFFF ))
        C=$(( (C + CC) & 0xFFFFFFFF ))
        D=$(( (D + DD) & 0xFFFFFFFF ))
    done

    # Sortie en little-endian (comme MD4 le spécifie)
    local ha hb hc hd
    endian::le32 "${A}" ha
    endian::le32 "${B}" hb
    endian::le32 "${C}" hc
    endian::le32 "${D}" hd
    _md4_hash_out="${ha}${hb}${hc}${hd}"
}
