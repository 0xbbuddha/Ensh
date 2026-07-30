#!/usr/bin/env bash
#
# tests/protocol/netbios/test_nbns_client_server.sh — Tests client/serveur NBNS
#

bk::import protocol/netbios/nbns

test::nbns_client_server_roundtrip() {
    local old_ip="${BK_NBNS_SERVER_IP:-}"
    local old_bind="${BK_NBNS_BIND_IP:-}"
    local old_port="${BK_NBNS_PORT:-}"
    local old_timeout="${BK_NBNS_TIMEOUT:-}"
    local old_suffix="${BK_NBNS_SUFFIX_HEX:-}"

    export BK_NBNS_SERVER_IP="127.0.0.1"
    export BK_NBNS_BIND_IP="127.0.0.1"
    export BK_NBNS_PORT="15137"
    export BK_NBNS_TIMEOUT="2"
    export BK_NBNS_SUFFIX_HEX="20"

    nbns::server::start "" "127.0.0.42"
    local rc=$?
    if (( rc != 0 )); then
        assert::equal "${rc}" "0" "démarrage du serveur NBNS"
        return 0
    fi

    declare -A parsed=()
    nbns::client::query parsed "FILESERVER" "127.0.0.1"
    rc=$?

    nbns::server::stop

    if [[ -n "${old_ip}" ]]; then export BK_NBNS_SERVER_IP="${old_ip}"; else unset BK_NBNS_SERVER_IP; fi
    if [[ -n "${old_bind}" ]]; then export BK_NBNS_BIND_IP="${old_bind}"; else unset BK_NBNS_BIND_IP; fi
    if [[ -n "${old_port}" ]]; then export BK_NBNS_PORT="${old_port}"; else unset BK_NBNS_PORT; fi
    if [[ -n "${old_timeout}" ]]; then export BK_NBNS_TIMEOUT="${old_timeout}"; else unset BK_NBNS_TIMEOUT; fi
    if [[ -n "${old_suffix}" ]]; then export BK_NBNS_SUFFIX_HEX="${old_suffix}"; else unset BK_NBNS_SUFFIX_HEX; fi

    assert::equal "${rc}" "0" "la requête client doit réussir"
    assert::equal "${parsed[answer_0_name]}" "FILESERVER" "nom renvoyé"
    assert::equal "${parsed[answer_0_ip]}" "127.0.0.42" "poisoning IPv4 attendu"
}
