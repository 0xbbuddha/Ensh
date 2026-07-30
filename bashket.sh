#!/usr/bin/env bash
#
# bashket.sh — Chargeur principal de la bibliothèque Bashket
#
# Usage :
#   source /path/to/bashket.sh             # Charge uniquement le core
#   source /path/to/bashket.sh --all       # Charge tous les modules
#   source /path/to/bashket.sh --ldap      # Charge la pile LDAP
#   source /path/to/bashket.sh --smb       # Charge la pile SMB/MSRPC
#
# Une fois chargé, on peut importer des modules à la demande :
#   bk::import crypto/nt_hash
#   bk::import protocol/ntlm
#
# ─────────────────────────────────────────────────────────────────────────────

# Protection contre le double-chargement
[[ -n "${_BK_LOADED:-}" ]] && return 0
readonly _BK_LOADED=1

# Résolution du chemin racine de la bibliothèque, même si l'on est sourcé
# depuis un répertoire différent. On ne redéclare pas si déjà défini (ex: par run_tests.sh).
if [[ -z "${BK_ROOT:-}" ]]; then
    BK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    readonly BK_ROOT
fi
readonly BK_LIB="${BK_ROOT}/lib"

# Version courante
readonly BK_VERSION="0.1.0"

# Bash 5.0 minimum requis (pour les tableaux associatifs améliorés, etc.)
if (( BASH_VERSINFO[0] < 5 )); then
    printf '[bashket] ERREUR : Bash >= 5.0 requis (actuel : %s)\n' "${BASH_VERSION}" >&2
    return 1
fi

# ── Registre des modules chargés ─────────────────────────────────────────────
#
# Clé   : chemin relatif du module (ex: "core/hex")
# Valeur: 1 si chargé
declare -gA _BK_MODULES=()

# ── Fonction d'import ────────────────────────────────────────────────────────
#
# bk::import <module> [module...]
#
# Charge un ou plusieurs modules par leur chemin relatif depuis lib/.
# Les imports redondants sont silencieusement ignorés (idempotent).
#
# Exemples :
#   bk::import core/hex
#   bk::import crypto/nt_hash protocol/ntlm
#
bk::import() {
    local module
    for module in "$@"; do
        # Déjà chargé ? On passe.
        [[ -n "${_BK_MODULES[${module}]:-}" ]] && continue

        local path="${BK_LIB}/${module}.sh"
        if [[ ! -f "${path}" ]]; then
            printf '[bashket] ERREUR : module introuvable : %s\n' "${module}" >&2
            return 1
        fi

        # Marquer avant le source pour éviter les cycles
        _BK_MODULES["${module}"]=1
        # shellcheck source=/dev/null
        source "${path}"
    done
}

# ── Chargement du core (toujours effectué) ────────────────────────────────────
bk::import \
    core/log   \
    core/hex   \
    core/bytes \
    core/endian

# ── Presets de chargement ────────────────────────────────────────────────────

bk::preset::ldap() {
    bk::import \
        protocol/ldap/message           \
        protocol/ldap/bind              \
        protocol/ldap/filter            \
        protocol/ldap/search            \
        protocol/ldap/modify            \
        protocol/ldap/add               \
        protocol/ldap/session
}

bk::preset::smb() {
    bk::import \
        protocol/netbios/nbt            \
        protocol/netbios/nbns           \
        protocol/ntlm/flags             \
        protocol/ntlm/negotiate         \
        protocol/ntlm/challenge         \
        protocol/ntlm/authenticate      \
        protocol/smb/spnego             \
        protocol/smb/smb1/header        \
        protocol/smb/smb1/negotiate     \
        protocol/smb/smb1/session_setup \
        protocol/smb/smb1/tree_connect  \
        protocol/smb/smb2/header        \
        protocol/smb/smb2/negotiate     \
        protocol/smb/smb2/session_setup \
        protocol/smb/smb2/tree_connect  \
        protocol/smb/smb2/ioctl         \
        protocol/smb/smb2/signing       \
        protocol/smb/smb2/create        \
        protocol/smb/smb2/read          \
        protocol/smb/smb2/write         \
        protocol/smb/smb2/close         \
        protocol/smb/smb2/query_directory \
        protocol/smb/smb3/signing       \
        protocol/smb/session            \
        protocol/dcerpc/bind            \
        protocol/dcerpc/request         \
        protocol/msrpc/srvsvc           \
        protocol/msrpc/samr             \
        protocol/msrpc/lsarpc
}

bk::preset::all() {
    bk::import \
        encoding/utf16          \
        encoding/base64         \
        encoding/asn1           \
        crypto/md4              \
        crypto/hmac_md5         \
        crypto/hmac_sha256      \
        crypto/aes_cmac         \
        crypto/rc4              \
        crypto/nt_hash          \
        crypto/lm_hash          \
        transport/tcp           \
        transport/udp           \
        transport/tls           \
        protocol/llmnr/message  \
        protocol/llmnr/client   \
        protocol/llmnr/server   \
        protocol/netbios/nbt    \
        protocol/netbios/nbns   \
        protocol/kerberos/asreq \
        protocol/kerberos/tgsreq

    bk::preset::ldap
    bk::preset::smb
}

# ── Chargement des presets demandés ──────────────────────────────────────────

case "${1:-}" in
    --all)
        bk::preset::all
        ;;
    --ldap)
        bk::preset::ldap
        ;;
    --smb)
        bk::preset::smb
        ;;
esac
