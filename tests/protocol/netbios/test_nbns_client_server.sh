#!/usr/bin/env bash
#
# tests/protocol/netbios/test_nbns_client_server.sh — Tests client/serveur NBNS
#

ensh::import protocol/netbios/nbns

test::nbns_client_server_roundtrip() {
    local old_ip="${ENSH_NBNS_SERVER_IP:-}"
    local old_bind="${ENSH_NBNS_BIND_IP:-}"
    local old_port="${ENSH_NBNS_PORT:-}"
    local old_timeout="${ENSH_NBNS_TIMEOUT:-}"
    local old_suffix="${ENSH_NBNS_SUFFIX_HEX:-}"

    export ENSH_NBNS_SERVER_IP="127.0.0.1"
    export ENSH_NBNS_BIND_IP="127.0.0.1"
    export ENSH_NBNS_PORT="15137"
    export ENSH_NBNS_TIMEOUT="2"
    export ENSH_NBNS_SUFFIX_HEX="20"

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

    if [[ -n "${old_ip}" ]]; then export ENSH_NBNS_SERVER_IP="${old_ip}"; else unset ENSH_NBNS_SERVER_IP; fi
    if [[ -n "${old_bind}" ]]; then export ENSH_NBNS_BIND_IP="${old_bind}"; else unset ENSH_NBNS_BIND_IP; fi
    if [[ -n "${old_port}" ]]; then export ENSH_NBNS_PORT="${old_port}"; else unset ENSH_NBNS_PORT; fi
    if [[ -n "${old_timeout}" ]]; then export ENSH_NBNS_TIMEOUT="${old_timeout}"; else unset ENSH_NBNS_TIMEOUT; fi
    if [[ -n "${old_suffix}" ]]; then export ENSH_NBNS_SUFFIX_HEX="${old_suffix}"; else unset ENSH_NBNS_SUFFIX_HEX; fi

    assert::equal "${rc}" "0" "la requête client doit réussir"
    assert::equal "${parsed[answer_0_name]}" "FILESERVER" "nom renvoyé"
    assert::equal "${parsed[answer_0_ip]}" "127.0.0.42" "poisoning IPv4 attendu"
}
