#!/usr/bin/env bash
#
# lib/protocol/ntlm/negotiate.sh — Message NTLM Negotiate (Type 1)
#
# Le message Negotiate est le premier message de l'échange NTLM.
# Le client l'envoie pour indiquer ses capacités et demander un challenge.
#
# Structure du message (MS-NLMP §2.2.1.1) :
#   Signature       : 8 octets  — "NTLMSSP\0"
#   MessageType     : 4 octets  — 0x00000001
#   NegotiateFlags  : 4 octets
#   DomainNameFields: 8 octets  — (optionnel)
#   WorkstationFields: 8 octets — (optionnel)
#   Version         : 8 octets  — (optionnel)
#   Payload         : variable
#
# Référence : MS-NLMP §2.2.1.1
#
# Dépendances : core/hex, core/bytes, core/endian, protocol/ntlm/flags
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_NTLM_NEGOTIATE:-}" ]] && return 0
readonly _ENSH_PROTO_NTLM_NEGOTIATE=1

ensh::import core/hex
ensh::import core/bytes
ensh::import core/endian
ensh::import protocol/ntlm/flags

# Signature obligatoire de tout message NTLM
readonly NTLM_SIGNATURE="4E544C4D535350000"   # "NTLMSSP\0" (attention : 8 octets = 16 nibbles)
# Correction : 8 octets = 16 nibbles
readonly _NTLM_SIG="4E544C4D53535000"

# ── Flags NTLM Negotiate par défaut ───────────────────────────────────────────
#
# Choix typique d'un client Windows moderne :
#   - NTLMSSP_NEGOTIATE_56
#   - NTLMSSP_NEGOTIATE_128
#   - NTLMSSP_NEGOTIATE_NTLM
#   - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
#   - NTLMSSP_NEGOTIATE_ALWAYS_SIGN
#   - NTLMSSP_REQUEST_TARGET
#   - NTLMSSP_NEGOTIATE_OEM
#   - NTLMSSP_NEGOTIATE_UNICODE

# ntlm::negotiate::build <var_out> [domain] [workstation] [flags_hex]
#
# Construit un message NTLM Negotiate.
# Si domain ou workstation sont fournis, ils sont inclus dans le payload.
# Si flags_hex est omis, on utilise les flags par défaut.
#
# Exemple :
#   ntlm::negotiate::build msg
#   ntlm::negotiate::build msg "CORP" "WORKSTATION" "$(ntlm::flags::default_negotiate)"
ntlm::negotiate::build() {
    local -n _ntlm_neg_out="$1"
    local domain="${2:-}"
    local workstation="${3:-}"
    local flags_hex="${4:-}"

    # Flags par défaut si non spécifiés
    if [[ -z "${flags_hex}" ]]; then
        ntlm::flags::default_negotiate flags_hex
    fi

    # Encodage des champs domain et workstation (OEM, non UTF-16 dans Negotiate)
    local domain_hex="" workstation_hex=""
    hex::from_string "${domain}" domain_hex
    hex::from_string "${workstation}" workstation_hex

    local -i domain_len=$(( ${#domain_hex} / 2 ))
    local -i workstation_len=$(( ${#workstation_hex} / 2 ))

    # Le payload commence après le header fixe de 32 octets
    # (avec version : 40 octets, mais on met Version à zéro)
    local -i header_size=32
    local -i domain_offset="${header_size}"
    local -i workstation_offset=$(( header_size + domain_len ))

    # ── Header ────────────────────────────────────────────────────────────────
    local buf="${_NTLM_SIG}"                             # Signature  (8 octets)

    local msgtype; endian::le32 1 msgtype
    buf+="${msgtype}"                                    # MessageType (4 octets)

    local flags_le; endian::swap "${flags_hex}" flags_le
    # Les flags sont déjà en LE dans ntlm::flags
    buf+="${flags_hex}"                                  # NegotiateFlags (4 octets)

    # DomainNameFields : Len (2), MaxLen (2), Offset (4) — tout en LE
    local dlen_le; endian::le16 "${domain_len}" dlen_le
    local doff_le; endian::le32 "${domain_offset}" doff_le
    buf+="${dlen_le}${dlen_le}${doff_le}"               # DomainNameFields (8 octets)

    # WorkstationFields
    local wlen_le; endian::le16 "${workstation_len}" wlen_le
    local woff_le; endian::le32 "${workstation_offset}" woff_le
    buf+="${wlen_le}${wlen_le}${woff_le}"               # WorkstationFields (8 octets)

    # Version (8 octets) — on indique Windows 10 (10.0.19041)
    # MajorVersion=10, MinorVersion=0, BuildNumber=19041, NTLMRevisionCurrent=15
    buf+="0A00414B0000000F"

    # ── Payload ───────────────────────────────────────────────────────────────
    buf+="${domain_hex}"
    buf+="${workstation_hex}"

    _ntlm_neg_out="${buf^^}"
}

# ntlm::negotiate::parse <hex_msg> <var_flags_out> <var_domain_out> <var_workstation_out>
#
# Analyse un message Negotiate et extrait ses champs principaux.
ntlm::negotiate::parse() {
    local msg="${1^^}"
    local -n _ntlm_neg_parse_flags="$2"
    local -n _ntlm_neg_parse_domain="$3"
    local -n _ntlm_neg_parse_ws="$4"

    # Vérifier la signature
    local sig="${msg:0:16}"
    if [[ "${sig}" != "${_NTLM_SIG}" ]]; then
        log::error "ntlm::negotiate::parse : signature invalide"
        return 1
    fi

    # Flags à l'offset 12 (bytes 12-15)
    bytes::read "${msg}" 12 4 _ntlm_neg_parse_flags

    # DomainNameFields à l'offset 16
    local dlen; endian::read_le16 "${msg}" 16 dlen
    local doff; endian::read_le32 "${msg}" 20 doff

    # WorkstationFields à l'offset 24
    local wlen; endian::read_le16 "${msg}" 24 wlen
    local woff; endian::read_le32 "${msg}" 28 woff

    # Extraire depuis le payload
    hex::slice "${msg}" "${doff}" "${dlen}" _ntlm_neg_parse_domain
    hex::slice "${msg}" "${woff}" "${wlen}" _ntlm_neg_parse_ws
}
