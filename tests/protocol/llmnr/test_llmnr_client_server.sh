#!/usr/bin/env bash
#
# tests/protocol/llmnr/test_llmnr_client_server.sh — Tests client/serveur LLMNR
#

bk::import protocol/llmnr/client
bk::import protocol/llmnr/server

test::llmnr_client_server_roundtrip() {
    local old_ip="${BK_LLMNR_SERVER_IP:-}"
    local old_bind="${BK_LLMNR_BIND_IP:-}"
    local old_port="${BK_LLMNR_PORT:-}"
    local old_timeout="${BK_LLMNR_TIMEOUT:-}"

    export BK_LLMNR_SERVER_IP="127.0.0.1"
    export BK_LLMNR_BIND_IP="127.0.0.1"
    export BK_LLMNR_PORT="15355"
    export BK_LLMNR_TIMEOUT="2"

    llmnr::server::start "" "127.0.0.42"
    local rc=$?
    if (( rc != 0 )); then
        assert::equal "${rc}" "0" "démarrage du serveur LLMNR"
        return 0
    fi

    declare -A parsed=()
    llmnr::client::query parsed "fileserver"
    rc=$?

    llmnr::server::stop

    if [[ -n "${old_ip}" ]]; then export BK_LLMNR_SERVER_IP="${old_ip}"; else unset BK_LLMNR_SERVER_IP; fi
    if [[ -n "${old_bind}" ]]; then export BK_LLMNR_BIND_IP="${old_bind}"; else unset BK_LLMNR_BIND_IP; fi
    if [[ -n "${old_port}" ]]; then export BK_LLMNR_PORT="${old_port}"; else unset BK_LLMNR_PORT; fi
    if [[ -n "${old_timeout}" ]]; then export BK_LLMNR_TIMEOUT="${old_timeout}"; else unset BK_LLMNR_TIMEOUT; fi

    assert::equal "${rc}" "0" "la requête client doit réussir"
    assert::equal "${parsed[question_name]}" "fileserver" "question renvoyée"
    assert::equal "${parsed[answer_0_ip]}" "127.0.0.42" "poisoning IPv4 attendu"
}
