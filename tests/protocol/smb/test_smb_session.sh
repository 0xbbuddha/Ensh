#!/usr/bin/env bash
#
# tests/protocol/smb/test_smb_session.sh — Tests pour lib/protocol/smb/session.sh
#

ensh::import protocol/smb/session

test::smb_session_dfs_flags_default_off() {
    local sess="test-dfs-default"
    _SMB_SERVER_CAPS["${sess}"]="${SMB2_CAP_DFS}"
    unset ENSH_SMB2_FORCE_DFS

    local out
    out="$(smb::_smb2_dfs_hdr_flags "${sess}")"
    assert::equal "${out}" "0" "DFS flag désactivé par défaut"

    unset "_SMB_SERVER_CAPS[${sess}]"
}

test::smb_session_dfs_flags_force_opt_in() {
    local sess="test-dfs-force"
    _SMB_SERVER_CAPS["${sess}"]="${SMB2_CAP_DFS}"
    unset ENSH_SMB2_FORCE_DFS
    ENSH_SMB2_FORCE_DFS=1

    local out
    out="$(smb::_smb2_dfs_hdr_flags "${sess}")"
    assert::equal "${out}" "$(( SMB2_FLAGS_DFS_OPERATIONS ))" "DFS flag activé en opt-in"

    unset ENSH_SMB2_FORCE_DFS
    unset "_SMB_SERVER_CAPS[${sess}]"
}

test::smb_session_normalize_pipe_name() {
    local out

    out="$(smb::_normalize_pipe_name '\srvsvc')"
    assert::equal "${out}" "srvsvc" "un pipe SMB2 ne doit pas commencer par un antislash"

    out="$(smb::_normalize_pipe_name '\\srvsvc')"
    assert::equal "${out}" "srvsvc" "plusieurs antislashs initiaux sont supprimés"

    out="$(smb::_normalize_pipe_name 'srvsvc')"
    assert::equal "${out}" "srvsvc" "un nom déjà normalisé reste inchangé"
}
