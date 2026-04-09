#!/usr/bin/env bash
#
# lib/crypto/nt_hash.sh — NT Hash (NTLM password hash)
#
# Le NT hash est défini comme :
#   NT = MD4( UTF-16LE( password ) )
#
# C'est la brique fondamentale de l'authentification NTLM/NTLMv2 et de
# nombreux mécanismes Windows (pass-the-hash, Kerberos RC4).
#
# Référence : MS-NLMP §3.3.1
#
# Dépendances : crypto/md4, encoding/utf16
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_CRYPTO_NT_HASH:-}" ]] && return 0
readonly _ENSH_CRYPTO_NT_HASH=1

ensh::import crypto/md4
ensh::import encoding/utf16

# nt_hash::from_password <password_string> <var_out>
#
# Calcule le NT hash d'un mot de passe en clair.
#   nt_hash::from_password "Password" out
#   → out="8846F7EAEE8FB117AD06BDD830B7586C"
nt_hash::from_password() {
    local password="$1"
    local -n _nth_fp_out="$2"

    local utf16
    utf16::encode_le "${password}" utf16

    md4::hash "${utf16}" _nth_fp_out
}

# nt_hash::from_hex_password <hex_password_utf16le> <var_out>
#
# Calcule le NT hash depuis un mot de passe déjà encodé en UTF-16LE hex.
nt_hash::from_hex_password() {
    md4::hash "$1" "$2"
}
