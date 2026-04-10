#!/usr/bin/env bash
#
# lib/protocol/smb/session.sh — API haut niveau SMB (v1 et v2)
#
# Fournit une interface unifiée pour établir une session SMB complète,
# en détectant automatiquement si le serveur parle SMB1 ou SMB2.
#
# Flux complet :
#
#   smb::session::connect   sess "10.10.10.1"          # TCP port 445
#   smb::session::negotiate "${sess}"                   # auto-détecte SMB1/SMB2
#   smb::session::login     "${sess}" "user" "DOM" "pw" # NTLMv2 via SPNEGO
#   smb::session::tree_connect "${sess}" "IPC$" tid     # se connecter à un partage
#   smb::session::tree_disconnect "${sess}" "${tid}"
#   smb::session::disconnect "${sess}"
#
# Registre de sessions (clé = "host:port:pid:RANDOM") :
#   _SMB_TCP[k]         — handle TCP
#   _SMB_HOST[k]        — hôte
#   _SMB_PORT[k]        — port
#   _SMB_VERSION[k]     — "1" ou "2" (détecté au Negotiate)
#   _SMB_PID[k]         — PID du processus (SMB1 : inclus dans les headers)
#   _SMB_SESSION_KEY[k] — SessionKey du Negotiate SMB1
#   _SMB_EXT_SEC[k]     — "1" si extended security (SMB1)
#   _SMB_UID[k]         — UserID (SMB1)
#   _SMB_MSG_ID[k]      — compteur de MessageId (SMB2)
#   _SMB_SESSION_ID[k]  — SessionId 8 octets LE en hex (SMB2)
#
# Dépendances : transport/tcp, crypto/nt_hash,
#               protocol/ntlm/{negotiate,challenge,authenticate},
#               protocol/smb/spnego,
#               protocol/smb/smb1/{header,negotiate,session_setup,tree_connect},
#               protocol/smb/smb2/{header,negotiate,session_setup,tree_connect}
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB_SESSION:-}" ]] && return 0
readonly _ENSH_SMB_SESSION=1

ensh::import core/log
ensh::import transport/tcp
ensh::import crypto/nt_hash
ensh::import protocol/ntlm/negotiate
ensh::import protocol/ntlm/challenge
ensh::import protocol/ntlm/authenticate
ensh::import protocol/smb/spnego
ensh::import protocol/smb/smb1/header
ensh::import protocol/smb/smb1/negotiate
ensh::import protocol/smb/smb1/session_setup
ensh::import protocol/smb/smb1/tree_connect
ensh::import protocol/smb/smb2/header
ensh::import protocol/smb/smb2/negotiate
ensh::import protocol/smb/smb2/session_setup
ensh::import protocol/smb/smb2/tree_connect
ensh::import protocol/smb/smb2/ioctl
ensh::import protocol/smb/smb2/signing

# ── Registre de sessions ──────────────────────────────────────────────────────

declare -gA _SMB_TCP=()
declare -gA _SMB_HOST=()
declare -gA _SMB_PORT=()
declare -gA _SMB_VERSION=()
declare -gA _SMB_PID=()
declare -gA _SMB_SESSION_KEY=()
declare -gA _SMB_EXT_SEC=()
declare -gA _SMB_UID=()              # SMB1 User ID
declare -gA _SMB_MSG_ID=()           # SMB2 MessageId counter
declare -gA _SMB_TREE_IPC=()         # TreeId du partage IPC$ (SMB2)
declare -gA _SMB_SESSION_ID=()       # SMB2 SessionId (hex 16 nibbles LE)
declare -gA _SMB_DIALECT=()          # dialecte SMB2 négocié (entier)
declare -gA _SMB_SIGNING_KEY=()      # clé de signature SMB2 dérivée
declare -gA _SMB_SIGNING_ENABLED=()  # "1" si signature active

# ── Primitives réseau ─────────────────────────────────────────────────────────

# smb::_send <session> <hex_data>
# Signe automatiquement si la signature est activée sur la session.
smb::_send() {
    local _sess="$1"
    local _data="${2^^}"

    if [[ "${_SMB_SIGNING_ENABLED[${_sess}]:-0}" == "1" ]]; then
        smb2::signing::sign_nbt _data \
            "${_SMB_SIGNING_KEY[${_sess}]}" \
            "${_SMB_DIALECT[${_sess}]:-0x0302}" || return 1
    fi

    tcp::send "${_SMB_TCP[${_sess}]}" "${_data}"
}

# smb::_recv <session> <var_out> [timeout]
# Lit un message NBT complet (header 4 octets + payload) et retourne le payload.
smb::_recv() {
    local _sess="$1"
    local -n _smb_recv_out="$2"
    local -i _timeout="${3:-30}"

    local _nbt_hdr
    tcp::recv "${_SMB_TCP[${_sess}]}" 4 _nbt_hdr "${_timeout}" || {
        log::error "smb::_recv : connexion fermée ou timeout"
        return 1
    }

    local -i _plen
    endian::read_be16 "${_nbt_hdr}" 2 _plen

    if (( _plen == 0 )); then
        _smb_recv_out=""
        return 0
    fi

    tcp::recv "${_SMB_TCP[${_sess}]}" "${_plen}" _smb_recv_out "${_timeout}"
}

# smb2::_next_msg_id <session> <var_out>
# Retourne le prochain MessageId SMB2 et incrémente le compteur.
smb2::_next_msg_id() {
    local _sess="$1"
    local -n _smb2_nmi_out="$2"
    _smb2_nmi_out="${_SMB_MSG_ID[${_sess}]}"
    (( _SMB_MSG_ID["${_sess}"]++ ))
}

# ── Connexion / Déconnexion ───────────────────────────────────────────────────

# smb::session::connect <var_sess_out> <host> [port] [timeout]
smb::session::connect() {
    local -n _smb_sc_out="$1"
    local host="$2"
    local -i port="${3:-445}"
    local -i timeout="${4:-10}"

    local _tcp_handle
    if ! tcp::connect "${host}" "${port}" _tcp_handle "${timeout}"; then
        log::error "smb::session::connect : impossible de joindre ${host}:${port}"
        return 1
    fi

    local _smb_key="${host}:${port}:$$:${RANDOM}"
    _SMB_TCP["${_smb_key}"]="${_tcp_handle}"
    _SMB_HOST["${_smb_key}"]="${host}"
    _SMB_PORT["${_smb_key}"]="${port}"
    _SMB_VERSION["${_smb_key}"]="?"
    _SMB_PID["${_smb_key}"]="${$}"
    _SMB_SESSION_KEY["${_smb_key}"]="0"
    _SMB_EXT_SEC["${_smb_key}"]="0"
    _SMB_UID["${_smb_key}"]="0"
    _SMB_MSG_ID["${_smb_key}"]="0"
    _SMB_SESSION_ID["${_smb_key}"]="0000000000000000"

    _smb_sc_out="${_smb_key}"
    log::info "smb : connecté à ${host}:${port}"
}

# smb::session::disconnect <session>
smb::session::disconnect() {
    local _sess="$1"
    local _handle="${_SMB_TCP[${_sess}]:-}"
    [[ -z "${_handle}" ]] && return 0

    tcp::close "${_handle}" 2>/dev/null || true

    unset "_SMB_TCP[${_sess}]"    "_SMB_HOST[${_sess}]"           "_SMB_PORT[${_sess}]"
    unset "_SMB_VERSION[${_sess}]" "_SMB_PID[${_sess}]"          "_SMB_SESSION_KEY[${_sess}]"
    unset "_SMB_EXT_SEC[${_sess}]" "_SMB_UID[${_sess}]"          "_SMB_MSG_ID[${_sess}]"
    unset "_SMB_SESSION_ID[${_sess}]" "_SMB_TREE_IPC[${_sess}]"  "_SMB_DIALECT[${_sess}]"
    unset "_SMB_SIGNING_KEY[${_sess}]" "_SMB_SIGNING_ENABLED[${_sess}]"
    log::debug "smb : session fermée"
}

# ── Négociation (auto-détecte SMB1 / SMB2) ───────────────────────────────────

# smb::session::negotiate <session>
#
# Stratégie d'auto-détection en deux phases :
#   1. Envoie d'abord un SMB2 NEGOTIATE natif (MessageId=0).
#      → Si le serveur répond en SMB2 (FE534D42) : session SMB2 configurée.
#   2. Si le serveur ferme la connexion (SMB1-only), ouvre une nouvelle
#      connexion TCP et envoie un SMB1 NEGOTIATE.
smb::session::negotiate() {
    local _sess="$1"
    local -i _pid="${_SMB_PID[${_sess}]}"
    local _host="${_SMB_HOST[${_sess}]}"
    local -i _port="${_SMB_PORT[${_sess}]}"

    # ── Phase 1 : SMB2 natif ──────────────────────────────────────────────
    local _req2
    smb2::negotiate::build_request _req2 0
    smb::_send "${_sess}" "${_req2}" || return 1

    local _resp
    if smb::_recv "${_sess}" _resp 10; then
        local _proto="${_resp:0:8}"

        if [[ "${_proto}" == "FE534D42" ]]; then
            _SMB_VERSION["${_sess}"]="2"
            _SMB_MSG_ID["${_sess}"]=1

            local -A _neg2
            smb2::negotiate::parse_response "${_resp}" _neg2 || return 1
            _SMB_DIALECT["${_sess}"]="${_neg2[dialect]}"
            log::info "smb : SMB2 négocié — dialecte=0x$(printf '%04X' ${_neg2[dialect]}) caps=0x$(printf '%08X' ${_neg2[capabilities]})"
            log::debug "smb2 : negotiate security_mode=0x$(printf '%04X' ${_neg2[security_mode]:-0}) (0x0001=signing_enabled, 0x0002=signing_required)"
            return 0
        fi
    fi

    # ── Phase 2 : SMB1 sur nouvelle connexion ─────────────────────────────
    # Le serveur a fermé la connexion (SMB1 seulement) ou répondu autrement.
    log::debug "smb : SMB2 refusé — tentative SMB1 sur nouvelle connexion"

    tcp::close "${_SMB_TCP[${_sess}]}" 2>/dev/null || true
    local _new_tcp
    if ! tcp::connect "${_host}" "${_port}" _new_tcp 10; then
        log::error "smb : reconnexion TCP échouée"
        return 1
    fi
    _SMB_TCP["${_sess}"]="${_new_tcp}"
    _SMB_MSG_ID["${_sess}"]=0

    local _req1
    smb1::negotiate::build_request _req1 "${_pid}" || return 1
    smb::_send "${_sess}" "${_req1}" || return 1

    smb::_recv "${_sess}" _resp 30 || {
        log::error "smb : le serveur SMB1 n'a pas répondu"
        return 1
    }

    if [[ "${_resp:0:8}" != "FF534D42" ]]; then
        log::error "smb : réponse inattendue (${_resp:0:8})"
        return 1
    fi

    _SMB_VERSION["${_sess}"]="1"
    local -A _neg1
    smb1::negotiate::parse_response "${_resp}" _neg1 || return 1

    if (( _neg1[status] != SMB1_STATUS_SUCCESS )); then
        log::error "smb1::negotiate : status=0x$(printf '%08X' ${_neg1[status]})"
        return 1
    fi

    _SMB_SESSION_KEY["${_sess}"]="${_neg1[session_key]:-0}"
    _SMB_EXT_SEC["${_sess}"]="${_neg1[ext_sec]}"
    log::info "smb : SMB1 négocié — ext_sec=${_neg1[ext_sec]} caps=0x$(printf '%08X' ${_neg1[capabilities]})"
}

# ── Authentification (NTLM sur SMB1 ou SMB2) ─────────────────────────────────

# smb::session::login <session> <username> <domain> <password>
smb::session::login() {
    local _sess="$1"
    local _user="$2"
    local _domain="$3"
    local _pass="$4"
    local _ver="${_SMB_VERSION[${_sess}]}"

    if [[ "${_ver}" == "2" ]]; then
        _smb2_login "${_sess}" "${_user}" "${_domain}" "${_pass}"
    elif [[ "${_ver}" == "1" ]]; then
        _smb1_login "${_sess}" "${_user}" "${_domain}" "${_pass}"
    else
        log::error "smb::login : version SMB inconnue (${_ver}) — appeler negotiate d'abord"
        return 1
    fi
}

# ── Implémentation interne : login SMB2 ──────────────────────────────────────

_smb2_login() {
    local _sess="$1"
    local _user="$2"
    local _domain="$3"
    local _pass="$4"

    # NT hash
    local _nt_hash
    nt_hash::from_password "${_pass}" _nt_hash

    # ── SessionSetup #1 : NTLM Negotiate ────────────────────────────────────
    local _ntlm_neg _spnego_init _msg_id1 _req1
    ntlm::negotiate::build _ntlm_neg "${_domain}" "" ""
    spnego::ntlm_init "${_ntlm_neg}" _spnego_init

    smb2::_next_msg_id "${_sess}" _msg_id1
    smb2::session_setup::build_ntlm_init _req1 "${_spnego_init}" "${_msg_id1}" \
        "${_SMB_SESSION_ID[${_sess}]}"
    smb::_send "${_sess}" "${_req1}" || return 1

    # ── Réponse #1 : NTLM Challenge ──────────────────────────────────────────
    local _resp1
    smb::_recv "${_sess}" _resp1 30 || return 1

    local -A _ss1
    smb2::session_setup::parse_response "${_resp1}" _ss1 || return 1

    if (( _ss1[status] != SMB2_STATUS_MORE_PROCESSING )); then
        log::error "smb2::login : STATUS_MORE_PROCESSING attendu, reçu 0x$(printf '%08X' ${_ss1[status]})"
        return 1
    fi

    # Conserver le SessionId du serveur pour la suite
    local _session_id="${_ss1[session_id]}"
    _SMB_SESSION_ID["${_sess}"]="${_session_id}"

    # Extraire le NTLM Challenge depuis le blob SPNEGO
    local _ntlm_challenge
    if ! spnego::find_ntlm "${_ss1[spnego_blob]}" _ntlm_challenge; then
        log::error "smb2::login : NTLM Challenge introuvable dans le blob SPNEGO"
        return 1
    fi

    local -A _chall
    ntlm::challenge::parse "${_ntlm_challenge}" _chall || return 1
    log::debug "smb2::login : challenge = ${_chall[server_challenge]}"

    # ── SessionSetup #2 : NTLM Authenticate ─────────────────────────────────
    local _ntlm_auth _spnego_auth _msg_id2 _req2
    log::debug "smb2::login : challenge flags = ${_chall[flags]}"
    local _exported_session_key=""
    ntlm::authenticate::build _ntlm_auth \
        "${_user}" "${_domain}" "ENSH" \
        "${_nt_hash}" \
        "${_chall[server_challenge]}" \
        "${_chall[target_info]}" \
        "${_chall[flags]}" "" "" \
        _exported_session_key

    spnego::ntlm_auth "${_ntlm_auth}" _spnego_auth

    smb2::_next_msg_id "${_sess}" _msg_id2
    smb2::session_setup::build_ntlm_auth _req2 "${_spnego_auth}" "${_msg_id2}" \
        "${_session_id}"
    smb::_send "${_sess}" "${_req2}" || return 1

    # ── Réponse finale ───────────────────────────────────────────────────────
    local _resp2
    smb::_recv "${_sess}" _resp2 30 || return 1

    local -A _ss2
    smb2::session_setup::parse_response "${_resp2}" _ss2 || return 1

    if (( _ss2[status] != SMB2_STATUS_SUCCESS )); then
        local -i _st="${_ss2[status]}"
        case "${_st}" in
            "${SMB2_STATUS_LOGON_FAILURE}"|"${SMB2_STATUS_WRONG_PASSWORD}")
                log::error "smb2::login : credentials invalides"
                ;;
            *) log::error "smb2::login : échec — status=0x$(printf '%08X' ${_st})" ;;
        esac
        return 1
    fi

    # Mise à jour du SessionId final
    local _final_sid="${_ss2[session_id]}"
    [[ "${_final_sid}" != "0000000000000000" ]] && _SMB_SESSION_ID["${_sess}"]="${_final_sid}"

    # Inspecter les SessionFlags : guest (0x01), null (0x02), chiffrement requis (0x04)
    local -i _sflags="${_ss2[session_flags]:-0}"
    local _guest=""
    (( _sflags & 0x0001 )) && _guest=" [GUEST]"
    log::info "smb2 : session_flags=0x$(printf '%04X' ${_sflags}) session_id=${_SMB_SESSION_ID[${_sess}]}"
    if (( _sflags & 0x0004 )); then
        log::warn "smb2 : le serveur exige le chiffrement SMB2 — non implémenté, TREE_CONNECT échouera"
    fi

    # ── Activation du signing SMB2 ────────────────────────────────────────────
    # Dériver la SigningKey depuis l'ExportedSessionKey NTLM
    if [[ -n "${_exported_session_key}" ]]; then
        log::info "smb2 : ExportedSessionKey=${_exported_session_key}"
        log::info "smb2 : SessionId KDF     =${_SMB_SESSION_ID[${_sess}]}"

        local _signing_key
        smb2::signing::derive_key _signing_key \
            "${_exported_session_key}" \
            "${_SMB_DIALECT[${_sess}]:-0x0302}" \
            "${_SMB_SESSION_ID[${_sess}]}" || true

        if [[ -n "${_signing_key}" ]]; then
            _SMB_SIGNING_KEY["${_sess}"]="${_signing_key}"
            _SMB_SIGNING_ENABLED["${_sess}"]="1"
            log::info "smb2 : signing activé (dialecte=0x$(printf '%04X' ${_SMB_DIALECT[${_sess}]:-0}) clé=${_signing_key})"

            # ── Vérification de la réponse serveur ─────────────────────────────
            # La réponse SESSION_SETUP finale est signée par le serveur (SMB 3.x).
            # Si notre clé est correcte, smb2::signing::verify doit passer.
            local -i _ss2_smb_flags; endian::read_le32 "${_resp2}" 16 _ss2_smb_flags
            if (( _ss2_smb_flags & SMB2_FLAGS_SIGNED )); then
                if smb2::signing::verify "${_resp2}" "${_signing_key}" "${_SMB_DIALECT[${_sess}]:-0x0302}"; then
                    log::info "smb2 : ✓ signature serveur SESSION_SETUP vérifiée — clé correcte"
                else
                    log::warn "smb2 : ✗ signature serveur SESSION_SETUP INVALIDE — clé de signing incorrecte !"
                fi
            else
                log::info "smb2 : réponse SESSION_SETUP non signée par le serveur (SMB2_FLAGS_SIGNED absent)"
            fi
        fi
    else
        log::warn "smb2 : ExportedSessionKey vide — KEY_EXCH absent ou RC4 échoué, signing désactivé"
    fi

    log::info "smb2 : authentifié en tant que ${_domain}\\${_user}${_guest}"
}

# ── Implémentation interne : login SMB1 ──────────────────────────────────────

_smb1_login() {
    local _sess="$1"
    local _user="$2"
    local _domain="$3"
    local _pass="$4"
    local -i _pid="${_SMB_PID[${_sess}]}"
    local -i _skey="${_SMB_SESSION_KEY[${_sess}]}"

    local _nt_hash
    nt_hash::from_password "${_pass}" _nt_hash

    local _ntlm_neg _spnego_init _req1
    ntlm::negotiate::build _ntlm_neg "${_domain}" "" ""
    spnego::ntlm_init "${_ntlm_neg}" _spnego_init
    smb1::session_setup::build_ntlm_init _req1 "${_spnego_init}" "${_pid}" "${_skey}"

    smb::_send "${_sess}" "${_req1}" || return 1

    local _resp1
    smb::_recv "${_sess}" _resp1 30 || return 1

    local -A _ss1
    smb1::session_setup::parse_response "${_resp1}" _ss1 || return 1

    if (( _ss1[status] != SMB1_STATUS_MORE_PROCESSING )); then
        log::error "smb1::login : MORE_PROCESSING attendu, reçu 0x$(printf '%08X' ${_ss1[status]})"
        return 1
    fi

    local -i _uid="${_ss1[uid]}"

    local _ntlm_challenge
    if ! spnego::find_ntlm "${_ss1[spnego_blob]}" _ntlm_challenge; then
        log::error "smb1::login : NTLM Challenge introuvable"
        return 1
    fi

    local -A _chall
    ntlm::challenge::parse "${_ntlm_challenge}" _chall || return 1

    local _ntlm_auth _spnego_auth _req2
    ntlm::authenticate::build _ntlm_auth \
        "${_user}" "${_domain}" "ENSH" \
        "${_nt_hash}" \
        "${_chall[server_challenge]}" \
        "${_chall[target_info]}"

    spnego::ntlm_auth "${_ntlm_auth}" _spnego_auth
    smb1::session_setup::build_ntlm_auth _req2 "${_spnego_auth}" "${_uid}" "${_pid}" "${_skey}"

    smb::_send "${_sess}" "${_req2}" || return 1

    local _resp2
    smb::_recv "${_sess}" _resp2 30 || return 1

    local -A _ss2
    smb1::session_setup::parse_response "${_resp2}" _ss2 || return 1

    if (( _ss2[status] != SMB1_STATUS_SUCCESS )); then
        log::error "smb1::login : échec — status=0x$(printf '%08X' ${_ss2[status]})"
        return 1
    fi

    local -i _final_uid="${_ss2[uid]}"
    (( _final_uid != 0 )) && _uid="${_final_uid}"
    _SMB_UID["${_sess}"]="${_uid}"
    log::info "smb1 : authentifié en tant que ${_domain}\\${_user} (uid=${_uid})"
}

# ── TreeConnect ───────────────────────────────────────────────────────────────

# smb::session::tree_connect <session> <share_name> <var_tid_out> [service]
smb::session::tree_connect() {
    local _sess="$1"
    local _share="$2"
    local -n _smb_tc_tid_out="$3"
    local _service="${4:-?????}"
    local _host="${_SMB_HOST[${_sess}]}"
    local _unc="\\\\${_host}\\${_share}"

    if [[ "${_SMB_VERSION[${_sess}]}" == "2" ]]; then
        local _msg_id; smb2::_next_msg_id "${_sess}" _msg_id
        local _req
        smb2::tree_connect::build_request _req "${_unc}" "${_msg_id}" \
            "${_SMB_SESSION_ID[${_sess}]}"
        smb::_send "${_sess}" "${_req}" || return 1

        local _resp
        smb::_recv "${_sess}" _resp 30 || return 1

        local -A _tc
        smb2::tree_connect::parse_response "${_resp}" _tc || return 1
        _smb_tc_tid_out="${_tc[tree_id]}"
        log::info "smb2 : partage '${_share}' connecté (tid=${_tc[tree_id]} type=${_tc[share_type]})"

    else
        local -i _uid="${_SMB_UID[${_sess}]}"
        local -i _mid=$(( RANDOM % 65534 + 4 ))
        local _req
        smb1::tree_connect::build_request _req "${_uid}" "${_unc}" "${_mid}" \
            "${_SMB_PID[${_sess}]}" "${_service}"
        smb::_send "${_sess}" "${_req}" || return 1

        local _resp
        smb::_recv "${_sess}" _resp 30 || return 1

        local -A _tc
        smb1::tree_connect::parse_response "${_resp}" _tc || return 1
        _smb_tc_tid_out="${_tc[tid]}"
        log::info "smb1 : partage '${_share}' connecté (tid=${_tc[tid]})"
    fi
}

# smb::session::tree_disconnect <session> <tid>
smb::session::tree_disconnect() {
    local _sess="$1"
    local -i _tid="$2"

    if [[ "${_SMB_VERSION[${_sess}]}" == "2" ]]; then
        local _msg_id; smb2::_next_msg_id "${_sess}" _msg_id
        local _req
        smb2::tree_disconnect::build_request _req "${_msg_id}" \
            "${_SMB_SESSION_ID[${_sess}]}" "${_tid}"
        smb::_send "${_sess}" "${_req}" || true
        local _resp; smb::_recv "${_sess}" _resp 5 || true

    else
        local -i _uid="${_SMB_UID[${_sess}]}"
        local _hdr
        smb1::header::build _hdr "${SMB1_CMD_TREE_DISCONNECT}" \
            "${_tid}" "${_SMB_PID[${_sess}]}" "${_uid}" 5
        local _smb="${_hdr}000000"
        local _req; smb1::nbt_wrap "${_smb}" _req
        smb::_send "${_sess}" "${_req}" || true
        local _resp; smb::_recv "${_sess}" _resp 5 || true
    fi

    log::debug "smb : tree disconnect tid=${_tid}"
}

# ── Utilitaires SMB2 : named pipes ───────────────────────────────────────────

# smb::session::open_pipe <session> <pipe_name> <var_file_id_out>
#
# Ouvre un named pipe sur IPC$ via SMB2 CREATE.
# <pipe_name> : ex "\srvsvc", "\samr", "\lsarpc"
# <var_file_id_out> : reçoit le FileId (32 nibbles hex = Persistent(8B) + Volatile(8B))
#
# Connecte automatiquement IPC$ si pas encore fait.
smb::session::open_pipe() {
    local _sess="$1"
    local _pipe="$2"
    local -n _smb_op_fid="$3"

    [[ "${_SMB_VERSION[${_sess}]}" != "2" ]] && {
        log::error "smb::session::open_pipe : SMB2 requis"
        return 1
    }

    # Connecter IPC$ si pas encore fait
    if [[ -z "${_SMB_TREE_IPC[${_sess}]:-}" ]]; then
        log::debug "smb::session::open_pipe : connexion à IPC\$..."
        local _ipc_tid
        if ! smb::session::tree_connect "${_sess}" "IPC\$" _ipc_tid; then
            log::error "smb::session::open_pipe : impossible de se connecter à IPC\$"
            return 1
        fi
        _SMB_TREE_IPC["${_sess}"]="${_ipc_tid}"
        log::debug "smb::session::open_pipe : IPC\$ tid=${_ipc_tid}"
    fi

    local -i _tid="${_SMB_TREE_IPC[${_sess}]}"
    local _sid="${_SMB_SESSION_ID[${_sess}]}"

    # SMB2 CREATE — ouvrir le named pipe
    # DesiredAccess : 0x001F01FF (GENERIC_ALL)
    # FileAttributes : 0 (pipe, pas de fichier)
    # ShareAccess : 3 (READ|WRITE)
    # CreateDisposition : OPEN_EXISTING = 1
    # CreateOptions : 0x00000040 (FILE_NON_DIRECTORY_FILE)
    # NameOffset : 64 + 56 (header + corps fixe) = 120
    local _msg_id; smb2::_next_msg_id "${_sess}" _msg_id

    local _pipe_utf16; utf16::encode_le "${_pipe}" _pipe_utf16
    local -i _name_len=$(( ${#_pipe_utf16} / 2 ))
    local _name_off_le _name_len_le; endian::le16 120 _name_off_le; endian::le16 "${_name_len}" _name_len_le

    local _hdr; smb2::header::build _hdr "${SMB2_CMD_CREATE}" "${_msg_id}" "${_sid}" "${_tid}" 0 0 1 1

    local _body="3900"          # StructureSize = 57
    _body+="00"                  # SecurityFlags = 0
    _body+="00"                  # RequestedOplockLevel = 0 (NONE)
    _body+="00000000"            # ImpersonationLevel = 0 (Anonymous)
    _body+="0000000000000000"    # SmbCreateFlags = 0
    _body+="0000000000000000"    # Reserved
    _body+="FF011F00"            # DesiredAccess = 0x001F01FF (LE)
    _body+="00000000"            # FileAttributes = 0
    _body+="03000000"            # ShareAccess = READ|WRITE
    _body+="01000000"            # CreateDisposition = OPEN_EXISTING
    _body+="40000000"            # CreateOptions = FILE_NON_DIRECTORY_FILE
    _body+="${_name_off_le}"     # NameOffset
    _body+="${_name_len_le}"     # NameLength
    _body+="00000000"            # CreateContextsOffset = 0
    _body+="00000000"            # CreateContextsLength = 0
    _body+="${_pipe_utf16}"      # FileName (UTF-16LE)

    local _smb="${_hdr}${_body}"; local _req; smb2::nbt_wrap "${_smb}" _req
    smb::_send "${_sess}" "${_req}" || return 1

    local _resp; smb::_recv "${_sess}" _resp 15 || return 1

    # Parse CREATE response
    local -A _cr_hdr; smb2::header::parse "${_resp}" _cr_hdr || return 1
    if (( _cr_hdr[status] != SMB2_STATUS_SUCCESS )); then
        log::error "smb::session::open_pipe : CREATE échoué status=0x$(printf '%08X' ${_cr_hdr[status]})"
        return 1
    fi

    # FileId : bytes 132-163 (offset 66 dans le corps = 64+66 = 130 octets = 260 nibbles)
    # Corps CREATE response : StructureSize(2) + OplockLevel(1) + Flags(1) + CreateAction(4)
    #   + CreationTime(8) + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8)
    #   + AllocationSize(8) + EndofFile(8) + FileAttributes(4) + Reserved2(4)
    #   + FileId(16) ...
    # Offset FileId = 64(header) + 2+1+1+4+8+8+8+8+8+8+4+4 = 64+64 = 128 octets = 256 nibbles
    hex::slice "${_resp}" 128 16 _smb_op_fid
    log::info "smb : pipe '${_pipe}' ouvert FileId=${_smb_op_fid:0:16}..."
}

# smb::session::close_pipe <session> <file_id_hex32>
#
# Ferme un named pipe ouvert via SMB2 CLOSE.
smb::session::close_pipe() {
    local _sess="$1"
    local _fid="$2"
    local -i _tid="${_SMB_TREE_IPC[${_sess}]:-0}"
    local _sid="${_SMB_SESSION_ID[${_sess}]}"

    local _msg_id; smb2::_next_msg_id "${_sess}" _msg_id
    local _hdr; smb2::header::build _hdr "${SMB2_CMD_CLOSE}" "${_msg_id}" "${_sid}" "${_tid}" 0 0 1 1

    local _body="1800"     # StructureSize = 24
    _body+="0000"          # Flags = 0
    _body+="00000000"      # Reserved
    _body+="${_fid}"       # FileId (16 octets)

    local _smb="${_hdr}${_body}"; local _req; smb2::nbt_wrap "${_smb}" _req
    smb::_send "${_sess}" "${_req}" || true
    local _resp; smb::_recv "${_sess}" _resp 5 || true
    log::debug "smb : pipe fermé"
}

# ── Utilitaire : try_share ────────────────────────────────────────────────────

# smb::session::try_share <session> <share_name> <var_result_out>
#
# Teste l'accessibilité d'un partage. Résultat : "OK", "ACCESS_DENIED",
# "NOT_FOUND", ou "ERROR:0xXXXXXXXX".
smb::session::try_share() {
    local _sess="$1"
    local _share="$2"
    local -n _smb_ts_out="$3"
    local _host="${_SMB_HOST[${_sess}]}"
    local _unc="\\\\${_host}\\${_share}"

    # Construire et envoyer la requête
    local _req
    if [[ "${_SMB_VERSION[${_sess}]}" == "2" ]]; then
        local _msg_id; smb2::_next_msg_id "${_sess}" _msg_id
        smb2::tree_connect::build_request _req "${_unc}" "${_msg_id}" \
            "${_SMB_SESSION_ID[${_sess}]}"
    else
        local -i _mid=$(( RANDOM % 65534 + 100 ))
        smb1::tree_connect::build_request _req "${_SMB_UID[${_sess}]}" \
            "${_unc}" "${_mid}" "${_SMB_PID[${_sess}]}"
    fi

    smb::_send "${_sess}" "${_req}" || { _smb_ts_out="ERROR:NETWORK"; return 1; }

    local _resp
    smb::_recv "${_sess}" _resp 10 || { _smb_ts_out="ERROR:TIMEOUT"; return 1; }

    # Lire le status depuis l'en-tête
    local -i _st
    if [[ "${_SMB_VERSION[${_sess}]}" == "2" ]]; then
        local -A _hdr2; smb2::header::parse "${_resp}" _hdr2 || { _smb_ts_out="ERROR:PARSE"; return 1; }
        _st="${_hdr2[status]}"
        if (( _st == SMB2_STATUS_SUCCESS )); then
            local _hdr2_tid="${_hdr2[tree_id]}"
            local _disc_req; local _disc_mid; smb2::_next_msg_id "${_sess}" _disc_mid
            smb2::tree_disconnect::build_request _disc_req "${_disc_mid}" \
                "${_SMB_SESSION_ID[${_sess}]}" "${_hdr2_tid}"
            smb::_send "${_sess}" "${_disc_req}" 2>/dev/null || true
            smb::_recv "${_sess}" _resp 5 2>/dev/null || true
        fi
    else
        local -A _hdr1; smb1::header::parse "${_resp}" _hdr1 || { _smb_ts_out="ERROR:PARSE"; return 1; }
        _st="${_hdr1[status]}"
        if (( _st == SMB1_STATUS_SUCCESS )); then
            smb::session::tree_disconnect "${_sess}" "${_hdr1[tid]}" 2>/dev/null || true
        fi
    fi

    local _success=$(( SMB2_STATUS_SUCCESS ))
    local _denied=$(( SMB2_STATUS_ACCESS_DENIED ))
    local _notfound=$(( SMB2_STATUS_BAD_NETWORK_NAME ))

    case "${_st}" in
        "${_success}")   _smb_ts_out="OK" ;;
        "${_denied}")    _smb_ts_out="ACCESS_DENIED" ;;
        "${_notfound}")  _smb_ts_out="NOT_FOUND" ;;
        *)               _smb_ts_out="ERROR:$(printf '0x%08X' ${_st})" ;;
    esac
}
