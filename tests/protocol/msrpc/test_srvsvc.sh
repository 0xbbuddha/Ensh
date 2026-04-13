#!/usr/bin/env bash
#
# tests/protocol/msrpc/test_srvsvc.sh — Tests SRVSVC / NDR
#

ensh::import protocol/msrpc/srvsvc

test::srvsvc_build_net_share_enum_stub() {
    local stub
    srvsvc::_build_net_share_enum_stub "DC01" stub

    local expected="00000200070000000000000007000000"
    expected+="5C005C00440043003000310000000000"
    expected+="01000000010000000100020000000000"
    expected+="00000000FFFFFFFF00000000"

    assert::equal "${stub}" "${expected}" "le stub NetrShareEnum niveau 1 doit être correctement ordonné"
}

test::srvsvc_parse_net_share_enum_resp_level1() {
    local stub="010000000100000008660000010000000A06000001000000"
    stub+="BAEA0000030000007D2E0000050000000000000005000000"
    stub+="49005000430024000000ABAB0B000000000000000B000000"
    stub+="520065006D006F007400650020004900500043000000BFBF"
    stub+="010000000000000000000000"

    local -a shares=()
    srvsvc::_parse_net_share_enum_resp "${stub}" shares

    assert::equal "${#shares[@]}" "1" "une entrée SHARE_INFO_1 doit être décodée"
    assert::equal "${shares[0]}" "IPC$:3:Remote IPC" "le nom, le type et le commentaire doivent être lus"
}

test::srvsvc_parse_net_share_enum_resp_multiple_entries() {
    local stub="010000000100000016BF000002000000A7E6000002000000"
    stub+="ADF100000000008029D50000AFE7000003000000DA360000"
    stub+="070000000000000007000000410044004D0049004E002400"
    stub+="0000ABAB0D000000000000000D000000520065006D006F00"
    stub+="740065002000410064006D0069006E000000ABAB05000000"
    stub+="000000000500000049005000430024000000ABAB0B000000"
    stub+="000000000B000000520065006D006F007400650020004900"
    stub+="500043000000BFBF020000000000000000000000"

    local -a shares=()
    srvsvc::_parse_net_share_enum_resp "${stub}" shares

    assert::equal "${#shares[@]}" "2" "deux entrées SHARE_INFO_1 doivent être décodées"
    assert::equal "${shares[0]}" "ADMIN$:2147483648:Remote Admin" "la première entrée doit rester alignée"
    assert::equal "${shares[1]}" "IPC$:3:Remote IPC" "la seconde entrée doit rester alignée"
}
