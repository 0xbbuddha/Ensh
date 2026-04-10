#!/usr/bin/env bash
#
# ensh.sh — Chargeur principal de la bibliothèque Ensh
#
# Usage :
#   source /path/to/ensh.sh             # Charge uniquement le core
#   source /path/to/ensh.sh --all       # Charge tous les modules
#
# Une fois chargé, on peut importer des modules à la demande :
#   ensh::import crypto/nt_hash
#   ensh::import protocol/ntlm
#
# ─────────────────────────────────────────────────────────────────────────────

# Protection contre le double-chargement
[[ -n "${_ENSH_LOADED:-}" ]] && return 0
readonly _ENSH_LOADED=1

# Résolution du chemin racine de la bibliothèque, même si l'on est sourcé
# depuis un répertoire différent. On ne redéclare pas si déjà défini (ex: par run_tests.sh).
if [[ -z "${ENSH_ROOT:-}" ]]; then
    ENSH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    readonly ENSH_ROOT
fi
readonly ENSH_LIB="${ENSH_ROOT}/lib"

# Version courante
readonly ENSH_VERSION="0.1.0"

# Bash 5.0 minimum requis (pour les tableaux associatifs améliorés, etc.)
if (( BASH_VERSINFO[0] < 5 )); then
    printf '[ensh] ERREUR : Bash >= 5.0 requis (actuel : %s)\n' "${BASH_VERSION}" >&2
    return 1
fi

# ── Registre des modules chargés ─────────────────────────────────────────────
#
# Clé   : chemin relatif du module (ex: "core/hex")
# Valeur: 1 si chargé
declare -gA _ENSH_MODULES=()

# ── Fonction d'import ────────────────────────────────────────────────────────
#
# ensh::import <module> [module...]
#
# Charge un ou plusieurs modules par leur chemin relatif depuis lib/.
# Les imports redondants sont silencieusement ignorés (idempotent).
#
# Exemples :
#   ensh::import core/hex
#   ensh::import crypto/nt_hash protocol/ntlm
#
ensh::import() {
    local module
    for module in "$@"; do
        # Déjà chargé ? On passe.
        [[ -n "${_ENSH_MODULES[${module}]:-}" ]] && continue

        local path="${ENSH_LIB}/${module}.sh"
        if [[ ! -f "${path}" ]]; then
            printf '[ensh] ERREUR : module introuvable : %s\n' "${module}" >&2
            return 1
        fi

        # Marquer avant le source pour éviter les cycles
        _ENSH_MODULES["${module}"]=1
        # shellcheck source=/dev/null
        source "${path}"
    done
}

# ── Chargement du core (toujours effectué) ────────────────────────────────────
ensh::import \
    core/log   \
    core/hex   \
    core/bytes \
    core/endian

# ── Mode "tout charger" ───────────────────────────────────────────────────────
if [[ "${1:-}" == "--all" ]]; then
    ensh::import \
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
        protocol/netbios/nbt          \
        protocol/ntlm/flags           \
        protocol/ntlm/negotiate       \
        protocol/ntlm/challenge       \
        protocol/ntlm/authenticate    \
        protocol/smb/spnego           \
        protocol/smb/smb1/header      \
        protocol/smb/smb1/negotiate   \
        protocol/smb/smb1/session_setup \
        protocol/smb/smb1/tree_connect  \
        protocol/smb/smb2/header        \
        protocol/smb/smb2/negotiate     \
        protocol/smb/smb2/session_setup \
        protocol/smb/smb2/tree_connect  \
        protocol/smb/smb2/ioctl         \
        protocol/smb/smb2/signing       \
        protocol/smb/session            \
        protocol/dcerpc/bind            \
        protocol/dcerpc/request         \
        protocol/msrpc/srvsvc           \
        protocol/ldap/message           \
        protocol/ldap/filter            \
        protocol/ldap/bind              \
        protocol/ldap/search            \
        protocol/ldap/session
fi
