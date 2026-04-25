#!/usr/bin/env bash
#
# tests/core/test_loader.sh — Validation du chargeur principal ensh.sh
#

test::ensh_loader_bash_syntax() {
    assert::returns_zero bash -n "${ENSH_ROOT}/ensh.sh"
}

test::ensh_loader_ldap_preset() {
    assert::returns_zero bash -lc \
        "source '${ENSH_ROOT}/ensh.sh' --ldap && \
         declare -F ldap::session::connect >/dev/null && \
         declare -F ldap::filter::equal >/dev/null"

    assert::returns_zero bash -lc \
        "source '${ENSH_ROOT}/ensh.sh' --ldap && \
         ! declare -F kerberos::asreq::build >/dev/null"
}

test::ensh_loader_smb_preset() {
    assert::returns_zero bash -lc \
        "source '${ENSH_ROOT}/ensh.sh' --smb && \
         declare -F smb::session::connect >/dev/null && \
         declare -F samr::bind >/dev/null && \
         declare -F lsarpc::bind >/dev/null && \
         ! declare -F ldap::session::connect >/dev/null"
}

test::ensh_loader_all_preset() {
    assert::returns_zero bash -lc \
        "source '${ENSH_ROOT}/ensh.sh' --all && \
         declare -F smb::session::connect >/dev/null && \
         declare -F ldap::session::connect >/dev/null && \
         declare -F kerberos::asreq::build >/dev/null && \
         declare -F llmnr::server::start >/dev/null"
}
