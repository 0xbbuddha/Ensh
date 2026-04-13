#!/usr/bin/env bash
#
# tests/protocol/dcerpc/test_dcerpc_bind.sh — Tests DCE/RPC BIND_ACK
#

ensh::import protocol/dcerpc/bind

test::dcerpc_bind_parse_ack_accept() {
    local ack_hex="05000C03100000003800000001000000"
    ack_hex+="B810B8107856341200000000"
    ack_hex+="01000000"
    ack_hex+="00000000045D888AEB1CC9119FE808002B10486002000000"

    local -A parsed=()
    dcerpc::bind::parse_ack "${ack_hex}" parsed

    assert::equal "${parsed[pkt_type]}" "${DCERPC_PKT_BIND_ACK}" "le type doit être BIND_ACK"
    assert::equal "${parsed[call_id]}" "1" "le CallId doit être conservé"
    assert::equal "${parsed[max_recv]}" "${DCERPC_MAX_FRAG}" "MaxRecvFrag doit être lu correctement"
    assert::equal "${parsed[assoc_grp]}" "$(( 0x12345678 ))" "AssocGroupId doit être lu correctement"
    assert::equal "${parsed[result]}" "${DCERPC_RESULT_ACCEPT}" "le contexte doit être accepté"
}
