#!/usr/bin/env bash
#
# lib/protocol/ntlm/flags.sh — Flags de négociation NTLM
#
# Définit toutes les constantes de flags NTLM (NegotiateFlags) telles que
# spécifiées dans MS-NLMP §2.2.2.5.
#
# Les flags sont stockés sous forme de chaînes hex LE 32 bits.
#
# Référence : MS-NLMP §2.2.2.5 (NTLMSSP_NEGOTIATE_*)
#
# Dépendances : core/endian
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_NTLM_FLAGS:-}" ]] && return 0
readonly _ENSH_PROTO_NTLM_FLAGS=1

ensh::import core/endian

# ── Constantes de flags (valeurs entières, masques de bits) ──────────────────

readonly NTLM_FL_UNICODE=$(( 1 << 0 ))                  # 0x00000001
readonly NTLM_FL_OEM=$(( 1 << 1 ))                      # 0x00000002
readonly NTLM_FL_REQUEST_TARGET=$(( 1 << 2 ))            # 0x00000004
readonly NTLM_FL_SIGN=$(( 1 << 4 ))                     # 0x00000010
readonly NTLM_FL_SEAL=$(( 1 << 5 ))                     # 0x00000020
readonly NTLM_FL_DATAGRAM=$(( 1 << 6 ))                 # 0x00000040
readonly NTLM_FL_LM_KEY=$(( 1 << 7 ))                   # 0x00000080
readonly NTLM_FL_NTLM=$(( 1 << 9 ))                     # 0x00000200
readonly NTLM_FL_ANONYMOUS=$(( 1 << 11 ))               # 0x00000800
readonly NTLM_FL_OEM_DOMAIN_SUPPLIED=$(( 1 << 12 ))     # 0x00001000
readonly NTLM_FL_OEM_WORKSTATION_SUPPLIED=$(( 1 << 13 )) # 0x00002000
readonly NTLM_FL_ALWAYS_SIGN=$(( 1 << 15 ))             # 0x00008000
readonly NTLM_FL_TARGET_TYPE_DOMAIN=$(( 1 << 16 ))      # 0x00010000
readonly NTLM_FL_TARGET_TYPE_SERVER=$(( 1 << 17 ))      # 0x00020000
readonly NTLM_FL_EXTENDED_SESS_SEC=$(( 1 << 19 ))       # 0x00080000
readonly NTLM_FL_IDENTIFY=$(( 1 << 20 ))                # 0x00100000
readonly NTLM_FL_NON_NT_SESSION_KEY=$(( 1 << 22 ))      # 0x00400000
readonly NTLM_FL_TARGET_INFO=$(( 1 << 23 ))             # 0x00800000
readonly NTLM_FL_VERSION=$(( 1 << 25 ))                 # 0x02000000
readonly NTLM_FL_128BIT=$(( 1 << 29 ))                  # 0x20000000
readonly NTLM_FL_KEY_EXCH=$(( 1 << 30 ))                # 0x40000000
readonly NTLM_FL_56BIT=$(( 1 << 31 ))                   # 0x80000000

# ── Helpers ───────────────────────────────────────────────────────────────────

# ntlm::flags::to_le32 <flags_int> <var_out>
#
# Convertit un entier de flags en chaîne hex little-endian 4 octets.
ntlm::flags::to_le32() {
    endian::le32 "$1" "$2"
}

# ntlm::flags::from_le32 <hex_le32> <var_out>
#
# Convertit une chaîne hex LE 4 octets en entier.
ntlm::flags::from_le32() {
    endian::read_le32 "$1" 0 "$2"
}

# ntlm::flags::has <flags_hex_le32> <flag_int>
#
# Retourne 0 si le flag est positionné, 1 sinon.
ntlm::flags::has() {
    local -i flags
    ntlm::flags::from_le32 "$1" flags
    (( (flags & $2) != 0 ))
}

# ntlm::flags::set <var_flags_le32> <flag_int>
#
# Active un flag dans une variable existante.
ntlm::flags::set() {
    local -n _ntlm_fl_set_var="$1"
    local -i current
    ntlm::flags::from_le32 "${_ntlm_fl_set_var}" current
    ntlm::flags::to_le32 "$(( current | $2 ))" _ntlm_fl_set_var
}

# ntlm::flags::clear <var_flags_le32> <flag_int>
ntlm::flags::clear() {
    local -n _ntlm_fl_clr_var="$1"
    local -i current
    ntlm::flags::from_le32 "${_ntlm_fl_clr_var}" current
    ntlm::flags::to_le32 "$(( current & ~($2) ))" _ntlm_fl_clr_var
}

# ntlm::flags::default_negotiate <var_out>
#
# Retourne les flags typiques d'un message Negotiate client.
ntlm::flags::default_negotiate() {
    local -i f=0
    (( f |= NTLM_FL_UNICODE ))
    (( f |= NTLM_FL_REQUEST_TARGET ))
    (( f |= NTLM_FL_NTLM ))
    (( f |= NTLM_FL_ALWAYS_SIGN ))
    (( f |= NTLM_FL_EXTENDED_SESS_SEC ))
    (( f |= NTLM_FL_VERSION ))      # signale la présence du champ Version
    (( f |= NTLM_FL_128BIT ))
    (( f |= NTLM_FL_KEY_EXCH ))  # requis pour exporter la session key (SMB signing)
    (( f |= NTLM_FL_56BIT ))
    ntlm::flags::to_le32 "${f}" "$1"
}

# ntlm::flags::describe <flags_hex_le32>
#
# Affiche une liste lisible des flags actifs (pour le débogage).
ntlm::flags::describe() {
    local hex="$1"
    local -i flags
    ntlm::flags::from_le32 "${hex}" flags

    local -A names=(
        ["${NTLM_FL_UNICODE}"]="UNICODE"
        ["${NTLM_FL_OEM}"]="OEM"
        ["${NTLM_FL_REQUEST_TARGET}"]="REQUEST_TARGET"
        ["${NTLM_FL_SIGN}"]="SIGN"
        ["${NTLM_FL_SEAL}"]="SEAL"
        ["${NTLM_FL_NTLM}"]="NTLM"
        ["${NTLM_FL_ALWAYS_SIGN}"]="ALWAYS_SIGN"
        ["${NTLM_FL_EXTENDED_SESS_SEC}"]="EXTENDED_SESS_SEC"
        ["${NTLM_FL_128BIT}"]="128BIT"
        ["${NTLM_FL_KEY_EXCH}"]="KEY_EXCHANGE"
        ["${NTLM_FL_56BIT}"]="56BIT"
    )

    local bit
    for bit in "${!names[@]}"; do
        if (( (flags & bit) != 0 )); then
            printf '  [+] %s\n' "${names[${bit}]}"
        fi
    done
}
