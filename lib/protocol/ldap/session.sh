#!/usr/bin/env bash
#
# lib/protocol/ldap/session.sh — Session LDAP haut niveau
#
# Ce module expose l'API publique d'Ensh pour LDAP. Il orchestre les
# modules inférieurs (transport, message, bind, search) pour offrir une
# interface simple et cohérente.
#
# Usage typique :
#
#   # 1. Ouvrir une session
#   ldap::session::connect session "dc01.corp.local" 389
#
#   # 2. S'authentifier
#   ldap::session::bind_simple session "cn=admin,dc=corp,dc=local" "P@ssw0rd"
#   # ou anonyme :
#   ldap::session::bind_anonymous session
#
#   # 3. Rechercher
#   ldap::filter::ad_spn filt
#   ldap::session::search session results \
#       "dc=corp,dc=local" "${LDAP_SCOPE_SUB}" "${filt}" \
#       "sAMAccountName" "servicePrincipalName"
#
#   # Parcourir les résultats
#   for i in "${!results[@]}"; do
#       declare -n entry="results_${i}"
#       echo "${entry[dn]}"
#       echo "${entry[attr:sAMAccountName]}"
#   done
#
#   # 4. Fermer
#   ldap::session::disconnect session
#
# Dépendances : transport/tcp, protocol/ldap/message,
#               protocol/ldap/bind, protocol/ldap/search
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LDAP_SESSION:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_SESSION=1

ensh::import core/log
ensh::import transport/tcp
ensh::import transport/tls
ensh::import protocol/ldap/message
ensh::import protocol/ldap/bind
ensh::import protocol/ldap/search

# ── Registre des sessions ─────────────────────────────────────────────────────
#
# Pour chaque session "s" :
#   _LDAP_TCP[s]       — handle de transport (TCP ou TLS selon _LDAP_TRANSPORT[s])
#   _LDAP_HOST[s]      — hôte
#   _LDAP_PORT[s]      — port
#   _LDAP_BOUND[s]     — "1" si authentifié
#   _LDAP_TRANSPORT[s] — "tcp" (plain LDAP) ou "tls" (LDAPS)

declare -gA _LDAP_TCP=()
declare -gA _LDAP_HOST=()
declare -gA _LDAP_PORT=()
declare -gA _LDAP_BOUND=()
declare -gA _LDAP_TRANSPORT=()

# ── Dispatchers de transport internes ─────────────────────────────────────────

# ldap::_transport_send <session> <hex_data>
ldap::_transport_send() {
    local _lts_session="$1"
    local _lts_hex="$2"
    local _lts_handle="${_LDAP_TCP[${_lts_session}]}"
    if [[ "${_LDAP_TRANSPORT[${_lts_session}]:-tcp}" == "tls" ]]; then
        tls::send "${_lts_handle}" "${_lts_hex}"
    else
        tcp::send "${_lts_handle}" "${_lts_hex}"
    fi
}

# ldap::_transport_recv <session> <n_bytes> <var_out> [timeout]
ldap::_transport_recv() {
    local _ltr_session="$1"
    local -i _ltr_n="$2"
    local -n _ltr_out="$3"
    local -i _ltr_timeout="${4:-30}"
    local _ltr_handle="${_LDAP_TCP[${_ltr_session}]}"
    if [[ "${_LDAP_TRANSPORT[${_ltr_session}]:-tcp}" == "tls" ]]; then
        tls::recv "${_ltr_handle}" "${_ltr_n}" _ltr_out "${_ltr_timeout}"
    else
        tcp::recv "${_ltr_handle}" "${_ltr_n}" _ltr_out "${_ltr_timeout}"
    fi
}

# ldap::_transport_close <session>
ldap::_transport_close() {
    local _ltc_session="$1"
    local _ltc_handle="${_LDAP_TCP[${_ltc_session}]}"
    if [[ "${_LDAP_TRANSPORT[${_ltc_session}]:-tcp}" == "tls" ]]; then
        tls::close "${_ltc_handle}"
    else
        tcp::close "${_ltc_handle}"
    fi
}

# ── Connexion ─────────────────────────────────────────────────────────────────

# ldap::session::connect <var_session_out> <host> [port] [timeout]
#
# Établit une connexion LDAP plain-text (port 389 par défaut).
ldap::session::connect() {
    local -n _ldap_conn_out="$1"
    local host="$2"
    local -i port="${3:-389}"
    local -i timeout="${4:-10}"

    local _ldap_tcp_handle
    if ! tcp::connect "${host}" "${port}" _ldap_tcp_handle "${timeout}"; then
        log::error "ldap::session : impossible de se connecter à ${host}:${port}"
        return 1
    fi

    local _ldap_sess_key="${host}:${port}:${RANDOM}"
    _LDAP_TCP["${_ldap_sess_key}"]="${_ldap_tcp_handle}"
    _LDAP_HOST["${_ldap_sess_key}"]="${host}"
    _LDAP_PORT["${_ldap_sess_key}"]="${port}"
    _LDAP_BOUND["${_ldap_sess_key}"]="0"
    _LDAP_TRANSPORT["${_ldap_sess_key}"]="tcp"

    ldap::message::reset_id
    _ldap_conn_out="${_ldap_sess_key}"
    log::info "ldap : connecté à ${host}:${port}"
}

# ldap::session::connect_tls <var_session_out> <host> [port] [timeout]
#
# Établit une connexion LDAPS (TLS) via openssl s_client.
# Port par défaut : 636 (LDAPS standard).
# Nécessite openssl en PATH.
ldap::session::connect_tls() {
    local -n _ldap_conn_tls_out="$1"
    local host="$2"
    local -i port="${3:-636}"
    local -i timeout="${4:-10}"

    local _ldap_tls_handle
    if ! tls::connect "${host}" "${port}" _ldap_tls_handle "${timeout}"; then
        log::error "ldap::session : impossible de se connecter à ${host}:${port} (TLS)"
        return 1
    fi

    local _ldap_sess_key="${host}:${port}:${RANDOM}"
    _LDAP_TCP["${_ldap_sess_key}"]="${_ldap_tls_handle}"
    _LDAP_HOST["${_ldap_sess_key}"]="${host}"
    _LDAP_PORT["${_ldap_sess_key}"]="${port}"
    _LDAP_BOUND["${_ldap_sess_key}"]="0"
    _LDAP_TRANSPORT["${_ldap_sess_key}"]="tls"

    ldap::message::reset_id
    _ldap_conn_tls_out="${_ldap_sess_key}"
    log::info "ldap : connecté à ${host}:${port} (LDAPS/TLS)"
}

# ldap::session::disconnect <session>
ldap::session::disconnect() {
    local session="$1"
    local handle="${_LDAP_TCP[${session}]:-}"
    [[ -z "${handle}" ]] && return 0

    # Envoyer un UnbindRequest si on est lié
    if [[ "${_LDAP_BOUND[${session}]}" == "1" ]]; then
        local unbind_req msg
        asn1::tlv "42" "" unbind_req      # [APPLICATION 2] NULL
        local mid; ldap::message::next_id mid
        ldap::message::wrap "${mid}" "${unbind_req}" msg
        ldap::_transport_send "${session}" "${msg}" 2>/dev/null || true
    fi

    ldap::_transport_close "${session}"
    unset "_LDAP_TCP[${session}]"
    unset "_LDAP_HOST[${session}]"
    unset "_LDAP_PORT[${session}]"
    unset "_LDAP_BOUND[${session}]"
    unset "_LDAP_TRANSPORT[${session}]"
    log::debug "ldap : session fermée"
}

# ── Authentification ──────────────────────────────────────────────────────────

# ldap::session::bind_simple <session> <dn> <password>
#
# Authentification simple (DN + mot de passe).
# Retourne 0 si succès, 1 si échec (mauvais credentials, etc.).
ldap::session::bind_simple() {
    local session="$1"
    local dn="$2"
    local password="$3"

    local req msg
    ldap::bind::simple "${dn}" "${password}" req

    local mid; ldap::message::next_id mid
    ldap::message::wrap "${mid}" "${req}" msg

    declare -A resp_dict=()
    ldap::_send_recv "${session}" "${msg}" "${mid}" resp_dict || return 1

    if [[ "${resp_dict[op_tag]}" != "61" ]]; then
        log::error "ldap::bind_simple : BindResponse attendu, tag=0x${resp_dict[op_tag]}"
        return 1
    fi

    declare -A bind_result=()
    ldap::bind::parse_response "${resp_dict[op_value]}" bind_result

    if ldap::bind::is_success bind_result; then
        _LDAP_BOUND["${session}"]="1"
        log::info "ldap : authentifié en tant que '${dn}'"
        return 0
    else
        log::error "ldap::bind_simple : échec (${bind_result[result_name]}) — ${bind_result[diagnostic_msg]}"
        return 1
    fi
}

# ldap::session::bind_anonymous <session>
#
# Connexion anonyme (lecture seule de la plupart des annuaires).
ldap::session::bind_anonymous() {
    ldap::session::bind_simple "$1" "" ""
}

# ── Recherche ─────────────────────────────────────────────────────────────────

# ldap::session::search <session> <results_var_prefix>
#                       <base_dn> <scope> <filter_hex>
#                       [attr...] [-- size_limit] [-- time_limit]
#
# Exécute une recherche LDAP et remplit des tableaux associatifs avec les résultats.
#
# Les entrées sont stockées dans des variables nommées <results_var_prefix>_0,
# <results_var_prefix>_1, etc. (tableaux associatifs dynamiques).
# Le nombre de résultats est dans <results_var_prefix>_count.
#
# Exemple :
#   ldap::session::search s "users" "dc=corp,dc=local" 2 "${filt}" \
#       "sAMAccountName" "mail"
#   echo "${users_count} résultats"
#   declare -n u="users_0"
#   echo "${u[dn]}"
#   echo "${u[attr:sAMAccountName]}"
ldap::session::search() {
    local session="$1"
    local prefix="$2"
    local base_dn="$3"
    local -i scope="$4"
    local filter="${5^^}"
    shift 5
    local -a attrs=("$@")

    local req msg
    ldap::search::build "${base_dn}" "${scope}" "${filter}" req \
        0 0 0 "${attrs[@]}"

    local mid; ldap::message::next_id mid
    ldap::message::wrap "${mid}" "${req}" msg

    ldap::_transport_send "${session}" "${msg}" || return 1

    local -i count=0
    # -g requis : printf -v crée une variable locale, pas globale
    declare -g "${prefix}_count=0"

    while true; do
        local raw_resp
        if ! ldap::_recv_msg "${session}" raw_resp; then
            log::warn "ldap::search : timeout ou connexion fermée après ${count} entrées"
            break
        fi

        declare -A resp_dict=()
        ldap::message::parse "${raw_resp}" resp_dict

        case "${resp_dict[op_tag]}" in
            64)  # SearchResultEntry (0x64)
                local entry_var="${prefix}_${count}"
                declare -gA "${entry_var}=()"
                local -n entry_ref="${entry_var}"
                ldap::search::parse_entry "${resp_dict[op_value]}" entry_ref
                (( count++ ))
                declare -g "${prefix}_count=${count}"
                ;;
            65)  # SearchResultDone (0x65)
                declare -A done_result=()
                ldap::message::parse_ldapresult "${resp_dict[op_value]}" done_result
                if [[ "${done_result[result_code]}" != "0" ]]; then
                    log::warn "ldap::search : ${done_result[result_name]} — ${done_result[diagnostic_msg]}"
                fi
                log::debug "ldap::search : ${count} entrée(s) reçue(s)"
                break
                ;;
            73)  # SearchResultReference — ignoré
                log::trace "ldap::search : référence ignorée"
                ;;
            *)
                log::warn "ldap::search : tag inattendu 0x${resp_dict[op_tag]}"
                break
                ;;
        esac
    done

    return 0
}

# ── Fonctions de commodité AD ─────────────────────────────────────────────────

# ldap::session::get_users <session> <results_prefix> <base_dn>
ldap::session::get_users() {
    local filt
    ldap::filter::ad_users filt
    ldap::session::search "$1" "$2" "$3" "${LDAP_SCOPE_SUB}" "${filt}" \
        "${LDAP_ATTRS_USER_BASIC[@]}"
}

# ldap::session::get_spn_accounts <session> <results_prefix> <base_dn>
#
# Récupère les comptes avec un SPN (candidats au Kerberoasting).
ldap::session::get_spn_accounts() {
    local filt
    ldap::filter::ad_spn filt
    ldap::session::search "$1" "$2" "$3" "${LDAP_SCOPE_SUB}" "${filt}" \
        "${LDAP_ATTRS_SPN[@]}"
}

# ldap::session::get_computers <session> <results_prefix> <base_dn>
ldap::session::get_computers() {
    local filt
    ldap::filter::ad_computers filt
    ldap::session::search "$1" "$2" "$3" "${LDAP_SCOPE_SUB}" "${filt}" \
        "${LDAP_ATTRS_COMPUTER[@]}"
}

# ldap::session::get_domain_info <session> <base_dn> <var_dict_out>
#
# Récupère les informations de base du domaine via le RootDSE ou l'objet de base.
ldap::session::get_domain_info() {
    local session="$1"
    local base_dn="$2"
    local -n _ldap_gdi_out="$3"

    local filt
    ldap::filter::equal "objectClass" "domain" filt

    ldap::session::search "${session}" "_ldap_gdi_tmp" "${base_dn}" \
        "${LDAP_SCOPE_BASE}" "${filt}" \
        "dc" "distinguishedName" "whenCreated" "objectGUID"

    if (( _ldap_gdi_tmp_count > 0 )); then
        local -n first="_ldap_gdi_tmp_0"
        # Copier dans le dict de sortie
        local key
        for key in "${!first[@]}"; do
            _ldap_gdi_out["${key}"]="${first[${key}]}"
        done
    fi
}

# ── Envoi/réception interne ───────────────────────────────────────────────────

# ldap::_send_recv <session> <hex_msg> <expected_msg_id> <var_resp_dict_name>
#
# Envoie un message et attend une réponse avec l'ID correspondant.
ldap::_send_recv() {
    local session="$1"
    local msg="${2^^}"
    local -i expected_id="$3"
    local -n _ldap_sr_resp="$4"

    ldap::_transport_send "${session}" "${msg}" || return 1

    local raw_resp
    if ! ldap::_recv_msg "${session}" raw_resp; then
        log::error "ldap::_send_recv : pas de réponse du serveur"
        return 1
    fi

    ldap::message::parse "${raw_resp}" _ldap_sr_resp
}

# ldap::_recv_msg <session> <var_hex_out>
#
# Lit un seul message LDAP depuis la connexion TCP.
# LDAP sur TCP n'utilise pas de framing — on lit un TLV BER complet.
#
# Lecture byte-à-byte pour le header BER afin d'éviter tout décalage
# de synchronisation : tag (1 byte) + premier octet de longueur (1 byte)
# + octets supplémentaires de longueur (0..4 bytes) + corps.
ldap::_recv_msg() {
    local session="$1"
    local -n _ldap_rm_out="$2"

    # 1. Tag (1 byte)
    local _tag_hex
    if ! ldap::_transport_recv "${session}" 1 _tag_hex 30; then
        return 1
    fi

    # 2. Premier octet de longueur (1 byte)
    local _first_len_hex
    if ! ldap::_transport_recv "${session}" 1 _first_len_hex 30; then
        return 1
    fi
    local -i _first_len=$(( 16#${_first_len_hex} ))

    local _header="${_tag_hex}${_first_len_hex}"
    local -i _total_len=0

    if (( (_first_len & 0x80) == 0 )); then
        # Forme courte : longueur sur 1 byte
        _total_len="${_first_len}"
    else
        # Forme longue : les nb bytes suivants encodent la longueur
        local -i _nb=$(( _first_len & 0x7F ))
        if (( _nb == 0 )); then
            log::error "_recv_msg : longueur BER indéfinie non supportée"
            return 1
        fi
        local _len_bytes_hex
        if ! ldap::_transport_recv "${session}" "${_nb}" _len_bytes_hex 30; then
            return 1
        fi
        _header+="${_len_bytes_hex}"
        _total_len=$(( 16#${_len_bytes_hex} ))
    fi

    # 3. Corps du message
    local _body_hex
    if ! ldap::_transport_recv "${session}" "${_total_len}" _body_hex 30; then
        return 1
    fi

    _ldap_rm_out="${_header}${_body_hex}"
    return 0
}
