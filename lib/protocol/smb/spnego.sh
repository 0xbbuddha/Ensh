#!/usr/bin/env bash
#
# lib/protocol/smb/spnego.sh — Encodage/décodage SPNEGO (RFC 4178)
#
# SPNEGO (Simple and Protected GSS-API Negotiation Mechanism) est le mécanisme
# utilisé par SMB pour négocier et envelopper les messages NTLMSSP (ou Kerberos).
#
# Structures ASN.1 implémentées :
#
#   NegTokenInit (envoyé par le client — premier SessionSetup) :
#     [60] Application    ← GSS-API wrapper
#       [30] SEQUENCE
#         [06] OID(SPNEGO)
#         [A0] [0] NegTokenInit
#           [30] SEQUENCE
#             [A0] mechTypes → SEQUENCE { OID(NTLMSSP) }
#             [A2] mechToken → OCTET STRING { NTLM Negotiate }
#
#   NegTokenResp (échanges suivants) :
#     [A1] [1] NegTokenResp
#       [30] SEQUENCE
#         [A0] negState     → ENUMERATED { accept-incomplete(1) | accept-completed(0) }
#         [A1] supportedMech → OID (optionnel)
#         [A2] responseToken → OCTET STRING { NTLM Challenge ou Authenticate }
#
# OIDs encodés en DER :
#   SPNEGO  : 1.3.6.1.5.5.2       → 06 06 2B 06 01 05 05 02
#   NTLMSSP : 1.3.6.1.4.1.311.2.2.10 → 06 0A 2B 06 01 04 01 82 37 02 02 0A
#
# Dépendances : core/log, encoding/asn1
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB_SPNEGO:-}" ]] && return 0
readonly _ENSH_SMB_SPNEGO=1

ensh::import core/log
ensh::import encoding/asn1

# ── OIDs en DER (précalculés) ─────────────────────────────────────────────────

# SPNEGO OID : 1.3.6.1.5.5.2 (6 octets de valeur)
readonly SPNEGO_OID_DER="06062B0601050502"

# NTLMSSP OID : 1.3.6.1.4.1.311.2.2.10 (10 octets de valeur)
# 311 en base-128 = 0x82 0x37
readonly SPNEGO_NTLMSSP_OID_DER="060A2B06010401823702020A"

# Signature NTLMSSP en hex (utilisée pour localiser un message NTLM dans un blob)
readonly SPNEGO_NTLM_SIG="4E544C4D53535000"

# ── Construction ──────────────────────────────────────────────────────────────

# spnego::ntlm_init <ntlm_negotiate_hex> <var_out>
#
# Construit un token SPNEGO NegTokenInit enveloppant un message NTLM Negotiate.
# À envoyer dans le premier SMB_COM_SESSION_SETUP_ANDX.
spnego::ntlm_init() {
    local ntlm_neg="${1^^}"
    local -n _spnego_ni_out="$2"

    # mechTypes [A0] = SEQUENCE { OID(NTLMSSP) }
    local _mech_seq _mech_types
    asn1::tlv "30" "${SPNEGO_NTLMSSP_OID_DER}" _mech_seq
    asn1::tlv "A0" "${_mech_seq}" _mech_types

    # mechToken [A2] = OCTET STRING { NTLM Negotiate }
    local _mech_tok_os _mech_tok
    asn1::tlv "04" "${ntlm_neg}" _mech_tok_os
    asn1::tlv "A2" "${_mech_tok_os}" _mech_tok

    # NegTokenInit [A0] = SEQUENCE { mechTypes, mechToken }
    local _neg_seq _neg_ctx
    asn1::tlv "30" "${_mech_types}${_mech_tok}" _neg_seq
    asn1::tlv "A0" "${_neg_seq}" _neg_ctx

    # GSS-API Application wrapper [APPLICATION 0 IMPLICIT] = OID(SPNEGO) + NegTokenInit
    # RFC 4178 §3.1 : InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE
    # → tag 0x60 remplace directement le SEQUENCE, pas de 0x30 intermédiaire.
    asn1::tlv "60" "${SPNEGO_OID_DER}${_neg_ctx}" _spnego_ni_out

    log::trace "spnego::ntlm_init : ${#_spnego_ni_out} nibbles"
}

# spnego::ntlm_auth <ntlm_authenticate_hex> <var_out>
#
# Construit un token SPNEGO NegTokenResp enveloppant un message NTLM Authenticate.
# À envoyer dans le troisième SMB_COM_SESSION_SETUP_ANDX.
spnego::ntlm_auth() {
    local ntlm_auth="${1^^}"
    local -n _spnego_na_out="$2"

    # responseToken [A2] = OCTET STRING { NTLM Authenticate }
    local _resp_os _resp_tok
    asn1::tlv "04" "${ntlm_auth}" _resp_os
    asn1::tlv "A2" "${_resp_os}" _resp_tok

    # NegTokenResp [A1] = SEQUENCE { responseToken }
    local _neg_seq
    asn1::tlv "30" "${_resp_tok}" _neg_seq
    asn1::tlv "A1" "${_neg_seq}" _spnego_na_out

    log::trace "spnego::ntlm_auth : ${#_spnego_na_out} nibbles"
}

# ── Extraction ────────────────────────────────────────────────────────────────

# spnego::find_ntlm <blob_hex> <var_ntlm_hex_out>
#
# Recherche et extrait un message NTLM (Negotiate, Challenge ou Authenticate)
# depuis un blob SPNEGO quelconque, en localisant la signature "NTLMSSP\0".
# Retourne 0 si trouvé, 1 sinon.
spnego::find_ntlm() {
    local blob="${1^^}"
    local -n _spnego_fn_out="$2"

    local -i blen=$(( ${#blob} / 2 ))
    local -i i

    for (( i = 0; i <= blen - 8; i++ )); do
        if [[ "${blob:$(( i * 2 )):16}" == "${SPNEGO_NTLM_SIG}" ]]; then
            _spnego_fn_out="${blob:$(( i * 2 ))}"
            log::trace "spnego::find_ntlm : NTLM trouvé à l'offset ${i}"
            return 0
        fi
    done

    log::debug "spnego::find_ntlm : signature NTLM introuvable dans le blob"
    return 1
}
