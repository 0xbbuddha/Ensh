#!/usr/bin/env bash
#
# lib/crypto/ntlmv1.sh — NTLMv1 Response (MS-NLMP §3.3.1)
#
# Calcule la réponse NTLMv1 (Challenge/Response sur 3 blocs DES).
# Utilisé pour cracker des hashes capturés (LLMNR/NBNS poisoning).
#
# Algorithme :
#   1. NT hash (16B) paddé à 21B (+5 octets zéro)
#   2. Divisé en 3 clés de 7 octets → expansion 7B→8B (56 bits → DES key)
#   3. DES-ECB du ServerChallenge (8B) avec chaque clé → 3×8B = 24B
#
# Référence : MS-NLMP §3.3.1, openssl enc -des-ecb
#
# Dépendances : core/log, crypto/nt_hash, crypto/lm_hash
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_NTLMV1:-}" ]] && return 0
readonly _ENSH_CRYPTO_NTLMV1=1

ensh::import core/log
ensh::import crypto/nt_hash
ensh::import crypto/lm_hash

# ── Helpers internes ─────────────────────────────────────────────────────────

# _ntlmv1_des_key <hex_7bytes> <var_out>
#
# Expand 7 octets (56 bits) → clé DES 8 octets pour openssl.
# Chaque octet de sortie contient 7 bits de clé en positions [7:1], bit 0 = parité 0.
_ntlmv1_des_key() {
    local h="${1^^}"
    local -n _ndk_out="$2"

    local -i b0=$(( 16#${h:0:2} ))  b1=$(( 16#${h:2:2} ))
    local -i b2=$(( 16#${h:4:2} ))  b3=$(( 16#${h:6:2} ))
    local -i b4=$(( 16#${h:8:2} ))  b5=$(( 16#${h:10:2} ))
    local -i b6=$(( 16#${h:12:2} ))

    printf -v _ndk_out '%02X%02X%02X%02X%02X%02X%02X%02X' \
        $(( ( b0 >> 1 )                               << 1 )) \
        $(( ( ((b0 & 0x01) << 6) | (b1 >> 2) )       << 1 )) \
        $(( ( ((b1 & 0x03) << 5) | (b2 >> 3) )       << 1 )) \
        $(( ( ((b2 & 0x07) << 4) | (b3 >> 4) )       << 1 )) \
        $(( ( ((b3 & 0x0F) << 3) | (b4 >> 5) )       << 1 )) \
        $(( ( ((b4 & 0x1F) << 2) | (b5 >> 6) )       << 1 )) \
        $(( ( ((b5 & 0x3F) << 1) | (b6 >> 7) )       << 1 )) \
        $(( ( b6 & 0x7F )                             << 1 ))
}

# _ntlmv1_des_ecb <hex_key_8bytes> <hex_plaintext_8bytes> <var_out>
#
# Chiffre 8 octets avec une clé DES 8 octets en mode ECB (via openssl).
_ntlmv1_des_ecb() {
    local key="${1^^}"
    local pt="${2^^}"
    local -n _nde_out="$3"

    local result
    result=$(
        for (( _i = 0; _i < ${#pt}; _i += 2 )); do
            printf "\\x${pt:${_i}:2}"
        done | \
        openssl enc -des-ecb -nopad -nosalt -provider legacy -provider default -K "${key}" 2>/dev/null | \
        od -An -tx1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]'
    )

    if [[ ${#result} -ne 16 ]]; then
        log::error "ntlmv1 : DES-ECB échoué — openssl requis"
        return 1
    fi

    _nde_out="${result}"
}

# ── API publique ──────────────────────────────────────────────────────────────

# ntlmv1::response <var_out> <nt_hash_hex> <server_challenge_hex>
#
# Calcule la réponse NTLMv1 (24 octets = 48 hex) depuis le NT hash.
ntlmv1::response() {
    local -n _nv1r_out="$1"
    local nt_hash="${2^^}"
    local challenge="${3^^}"

    if [[ ${#nt_hash} -ne 32 ]]; then
        log::error "ntlmv1::response : NT hash invalide (attendu 32 hex)"
        return 1
    fi
    if [[ ${#challenge} -ne 16 ]]; then
        log::error "ntlmv1::response : challenge invalide (attendu 16 hex)"
        return 1
    fi

    # Pad NT hash (16B) → 21B
    local padded="${nt_hash}0000000000"

    local k1 k2 k3
    _ntlmv1_des_key "${padded:0:14}"  k1 || return 1
    _ntlmv1_des_key "${padded:14:14}" k2 || return 1
    _ntlmv1_des_key "${padded:28:14}" k3 || return 1

    local r1 r2 r3
    _ntlmv1_des_ecb "${k1}" "${challenge}" r1 || return 1
    _ntlmv1_des_ecb "${k2}" "${challenge}" r2 || return 1
    _ntlmv1_des_ecb "${k3}" "${challenge}" r3 || return 1

    _nv1r_out="${r1}${r2}${r3}"
}

# ntlmv1::lm_response <var_out> <lm_hash_hex> <server_challenge_hex>
#
# Même structure que ntlmv1::response mais avec le LM hash.
ntlmv1::lm_response() {
    ntlmv1::response "$1" "$2" "$3"
}

# ntlmv1::compute <var_nt_out> <var_lm_out> <password> <server_challenge_hex>
#
# Raccourci : calcule NT et LM responses depuis le mot de passe en clair.
ntlmv1::compute() {
    local -n _nv1c_nt="$1"
    local -n _nv1c_lm="$2"
    local password="$3"
    local challenge="${4^^}"

    local nt_hash lm_hash
    nt_hash::from_password "${password}" nt_hash
    lm_hash::from_password "${password}" lm_hash

    ntlmv1::response    _nv1c_nt "${nt_hash}" "${challenge}" || return 1
    ntlmv1::lm_response _nv1c_lm "${lm_hash}" "${challenge}" || return 1
}

# ntlmv1::format_hashcat <user> <domain> <server_challenge_hex> <lm_response_hex> <nt_response_hex>
#
# Formate pour hashcat mode 5500 (NetNTLMv1) :
#   user::domain:LMResponse:NTResponse:ServerChallenge
ntlmv1::format_hashcat() {
    local user="$1"
    local domain="$2"
    local challenge="${3^^}"
    local lm_resp="${4^^}"
    local nt_resp="${5^^}"

    printf '%s::%s:%s:%s:%s\n' "${user}" "${domain}" "${lm_resp}" "${nt_resp}" "${challenge}"
}
