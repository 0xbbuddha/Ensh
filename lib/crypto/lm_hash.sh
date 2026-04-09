#!/usr/bin/env bash
#
# lib/crypto/lm_hash.sh — LM Hash (LAN Manager password hash)
#
# Algorithme historique, désactivé par défaut depuis Vista/2008.
# Conservé pour interopérabilité avec les systèmes anciens.
#
# Algorithme :
#   1. Tronquer/padder le mot de passe à 14 caractères (majuscules)
#   2. Découper en deux moitiés de 7 caractères
#   3. Chacune sert de clé DES pour chiffrer la constante "KGS!@#$%"
#   4. Concaténer les deux résultats (16 octets)
#
# Référence : MS-NLMP §3.3.1
#
# Note : l'implémentation DES pure en Bash est coûteuse.
# On s'appuie sur openssl des-ecb ; si absent, la fonction échoue proprement.
#
# Dépendances : core/hex, core/log
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_LM_HASH:-}" ]] && return 0
readonly _ENSH_CRYPTO_LM_HASH=1

ensh::import core/hex
ensh::import core/log

# La constante magique chiffrée par les deux moitiés de clé
readonly _LM_MAGIC="4B47532140232425"   # "KGS!@#$%"

# _lm::des_ecb <hex_key_7bytes> <hex_plaintext_8bytes> <var_out>
#
# Chiffrement DES-ECB d'un bloc de 8 octets avec une clé de 7 octets.
# La clé de 7 octets est étendue à 8 octets selon le schéma DES (expansion
# de parité des bits).
_lm::des_ecb() {
    local key7="${1^^}"
    local plain="${2^^}"
    local -n _lm_des_out="$3"

    if ! command -v openssl >/dev/null 2>&1; then
        log::die "lm_hash : openssl requis pour DES-ECB"
    fi

    # Expansion de la clé 7 octets → 8 octets DES (ajout du bit de parité)
    local -a k=()
    local -i i
    for (( i=0; i<7; i++ )); do
        k+=( $(( 16#${key7:$(( i*2 )):2} )) )
    done

    local -a dk=(
        $(( (k[0] >> 1) & 0xFE ))
        $(( ((k[0] << 6) | (k[1] >> 2)) & 0xFE ))
        $(( ((k[1] << 5) | (k[2] >> 3)) & 0xFE ))
        $(( ((k[2] << 4) | (k[3] >> 4)) & 0xFE ))
        $(( ((k[3] << 3) | (k[4] >> 5)) & 0xFE ))
        $(( ((k[4] << 2) | (k[5] >> 6)) & 0xFE ))
        $(( ((k[5] << 1) | (k[6] >> 7)) & 0xFE ))
        $(( (k[6] << 0) & 0xFE ))
    )

    local key8=""
    for b in "${dk[@]}"; do
        printf -v key8 '%s%02X' "${key8}" "${b}"
    done

    _lm_des_out="$(
        local i
        for (( i=0; i<${#plain}; i+=2 )); do
            printf "\\x${plain:${i}:2}"
        done | openssl enc -des-ecb -nosalt -nopad -K "${key8}" 2>/dev/null \
             | xxd -p | tr -d '\n'
    )"
    _lm_des_out="${_lm_des_out^^}"
}

# lm_hash::from_password <password_string> <var_out>
#
# Calcule le LM hash d'un mot de passe en clair.
lm_hash::from_password() {
    local password="$1"
    local -n _lmh_out="$2"

    # 1. Majuscules, tronquer à 14, padder avec 0x00
    local upper="${password^^}"
    upper="${upper:0:14}"
    local hex_pass
    hex::from_string "${upper}" hex_pass
    hex::pad_right "${hex_pass}" 14 hex_pass

    # 2. Deux moitiés de 7 octets
    local half1="${hex_pass:0:14}"
    local half2="${hex_pass:14:14}"

    # 3. Chiffrer la constante magique avec chaque moitié
    local enc1 enc2
    _lm::des_ecb "${half1}" "${_LM_MAGIC}" enc1
    _lm::des_ecb "${half2}" "${_LM_MAGIC}" enc2

    _lmh_out="${enc1}${enc2}"
}
