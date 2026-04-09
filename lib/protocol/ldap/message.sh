#!/usr/bin/env bash
#
# lib/protocol/ldap/message.sh — LDAPMessage : enveloppe BER
#
# LDAP utilise BER (Basic Encoding Rules, X.690) pour sérialiser ses messages.
# BER est similaire à DER mais autorise des variations dans l'encodage des
# longueurs. On produit du DER (sous-ensemble de BER) qui est toujours valide.
#
# Structure LDAPMessage (RFC 4511 §4.1.1) :
#   LDAPMessage ::= SEQUENCE {
#       messageID   MessageID,        -- INTEGER (0..maxInt)
#       protocolOp  CHOICE { ... },   -- Tag applicatif selon l'opération
#       controls   [0] OPTIONAL       -- Contrôles LDAP
#   }
#
# Tags applicatifs utilisés dans ce module :
#   [APPLICATION 0]  BindRequest
#   [APPLICATION 1]  BindResponse
#   [APPLICATION 3]  SearchRequest
#   [APPLICATION 4]  SearchResultEntry
#   [APPLICATION 5]  SearchResultDone
#   [APPLICATION 6]  ModifyRequest
#   [APPLICATION 7]  ModifyResponse
#   [APPLICATION 8]  AddRequest
#   [APPLICATION 9]  AddResponse
#   [APPLICATION 10] DelRequest
#   [APPLICATION 11] DelResponse
#   [APPLICATION 16] AbandonRequest
#   [APPLICATION 19] SearchResultReference
#   [APPLICATION 23] ExtendedRequest
#   [APPLICATION 24] ExtendedResponse
#
# Référence : RFC 4511 (LDAPv3)
#
# Dépendances : core/hex, core/bytes, core/endian, encoding/asn1
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LDAP_MESSAGE:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_MESSAGE=1

ensh::import core/hex
ensh::import core/bytes
ensh::import core/endian
ensh::import encoding/asn1

# ── Tags applicatifs LDAP ─────────────────────────────────────────────────────
#
# Tag applicatif construit = 0x60 | N   (classe Application, construit)
# Tag applicatif primitif  = 0x40 | N   (classe Application, primitif)

readonly LDAP_TAG_BIND_REQUEST=0x60          # [APPLICATION 0]  construit
readonly LDAP_TAG_BIND_RESPONSE=0x61         # [APPLICATION 1]  construit
readonly LDAP_TAG_UNBIND_REQUEST=0x42        # [APPLICATION 2]  primitif
readonly LDAP_TAG_SEARCH_REQUEST=0x63        # [APPLICATION 3]  construit
readonly LDAP_TAG_SEARCH_ENTRY=0x64          # [APPLICATION 4]  construit
readonly LDAP_TAG_SEARCH_DONE=0x65           # [APPLICATION 5]  construit
readonly LDAP_TAG_SEARCH_REF=0x73            # [APPLICATION 19] construit
readonly LDAP_TAG_MODIFY_REQUEST=0x66        # [APPLICATION 6]  construit
readonly LDAP_TAG_MODIFY_RESPONSE=0x67       # [APPLICATION 7]  construit
readonly LDAP_TAG_ADD_REQUEST=0x68           # [APPLICATION 8]  construit
readonly LDAP_TAG_ADD_RESPONSE=0x69          # [APPLICATION 9]  construit
readonly LDAP_TAG_DEL_REQUEST=0x4A           # [APPLICATION 10] primitif
readonly LDAP_TAG_DEL_RESPONSE=0x6B          # [APPLICATION 11] construit
readonly LDAP_TAG_ABANDON_REQUEST=0x50       # [APPLICATION 16] primitif
readonly LDAP_TAG_EXTENDED_REQUEST=0x77      # [APPLICATION 23] construit
readonly LDAP_TAG_EXTENDED_RESPONSE=0x78     # [APPLICATION 24] construit

# ── ResultCode LDAP (RFC 4511 §4.1.9) ────────────────────────────────────────

readonly LDAP_RC_SUCCESS=0
readonly LDAP_RC_OPERATIONS_ERROR=1
readonly LDAP_RC_PROTOCOL_ERROR=2
readonly LDAP_RC_TIME_LIMIT_EXCEEDED=3
readonly LDAP_RC_SIZE_LIMIT_EXCEEDED=4
readonly LDAP_RC_AUTH_METHOD_NOT_SUPPORTED=7
readonly LDAP_RC_STRONGER_AUTH_REQUIRED=8
readonly LDAP_RC_NO_SUCH_OBJECT=32
readonly LDAP_RC_ALIAS_PROBLEM=33
readonly LDAP_RC_INVALID_DN_SYNTAX=34
readonly LDAP_RC_INVALID_ATTRIBUTE_SYNTAX=21
readonly LDAP_RC_NO_SUCH_ATTRIBUTE=16
readonly LDAP_RC_INVALID_CREDENTIALS=49
readonly LDAP_RC_INSUFFICIENT_ACCESS_RIGHTS=50
readonly LDAP_RC_BUSY=51
readonly LDAP_RC_UNAVAILABLE=52
readonly LDAP_RC_UNWILLING_TO_PERFORM=53

# Descriptions lisibles des codes de résultat
readonly -A LDAP_RC_NAMES=(
    [0]="success"
    [1]="operationsError"
    [2]="protocolError"
    [3]="timeLimitExceeded"
    [4]="sizeLimitExceeded"
    [7]="authMethodNotSupported"
    [8]="strongerAuthRequired"
    [32]="noSuchObject"
    [49]="invalidCredentials"
    [50]="insufficientAccessRights"
    [53]="unwillingToPerform"
)

# ── Compteur de MessageID ─────────────────────────────────────────────────────
declare -gi _LDAP_MSG_ID=1

# ldap::message::next_id <var_out>
#
# Retourne le prochain MessageID (auto-incrément).
ldap::message::next_id() {
    local -n _ldap_nid_out="$1"
    _ldap_nid_out="${_LDAP_MSG_ID}"
    (( _LDAP_MSG_ID++ ))
}

# ldap::message::reset_id
#
# Remet le compteur à 1 (utile pour les tests reproductibles).
ldap::message::reset_id() {
    _LDAP_MSG_ID=1
}

# ── Construction d'un LDAPMessage ────────────────────────────────────────────

# ldap::message::wrap <message_id_int> <protocol_op_hex> <var_out> [controls_hex]
#
# Encapsule une opération dans une LDAPMessage SEQUENCE.
#
# Exemple :
#   ldap::message::wrap 1 "${bind_request_hex}" msg
ldap::message::wrap() {
    local -i msg_id="$1"
    local op="${2^^}"
    local -n _ldap_mw_out="$3"
    local controls="${4:-}"

    # MessageID ::= INTEGER — printf '%X' peut produire un nibble impair, on normalise
    local id_hex
    asn1::integer "$(printf '%02X' "${msg_id}")" id_hex

    # Contenu de la SEQUENCE : messageID + protocolOp [+ controls]
    local content="${id_hex}${op}"
    if [[ -n "${controls}" ]]; then
        # Controls [0] IMPLICIT SEQUENCE OF Control
        local ctrl_tlv
        asn1::tlv "A0" "${controls}" ctrl_tlv
        content+="${ctrl_tlv}"
    fi

    asn1::sequence "${content}" _ldap_mw_out
}

# ── Parsing d'un LDAPMessage ─────────────────────────────────────────────────

# ldap::message::parse <hex_msg> <var_dict_name>
#
# Parse une LDAPMessage et remplit un tableau associatif avec :
#   msg_id      — MessageID (entier)
#   op_tag      — Tag de l'opération (hex 1 octet)
#   op_value    — Valeur de l'opération (hex)
#   has_controls — "1" si des contrôles sont présents
ldap::message::parse() {
    local msg="${1^^}"
    local -n _ldap_mp_dict="$2"

    # Doit commencer par une SEQUENCE (0x30)
    if [[ "${msg:0:2}" != "30" ]]; then
        log::error "ldap::message::parse : SEQUENCE attendue, tag=0x${msg:0:2}"
        return 1
    fi

    local outer_tag outer_len outer_val outer_next
    asn1::parse_tlv "${msg}" 0 outer_tag outer_len outer_val outer_next

    # MessageID = premier TLV (INTEGER)
    local id_tag id_len id_val id_next
    asn1::parse_tlv "${outer_val}" 0 id_tag id_len id_val id_next
    if [[ "${id_tag}" != "02" ]]; then
        log::error "ldap::message::parse : MessageID INTEGER attendu"
        return 1
    fi
    hex::to_int "${id_val}" _ldap_mp_dict[msg_id]

    # ProtocolOp = deuxième TLV
    local op_tag op_len op_val op_next
    asn1::parse_tlv "${outer_val}" "${id_next}" op_tag op_len op_val op_next

    _ldap_mp_dict[op_tag]="${op_tag}"
    _ldap_mp_dict[op_value]="${op_val}"

    # Controls optionnels [0] = tag A0
    local remaining="${outer_val:$(( op_next * 2 ))}"
    if [[ -n "${remaining}" ]] && [[ "${remaining:0:2}" == "A0" ]]; then
        _ldap_mp_dict[has_controls]="1"
        local ctrl_tag ctrl_len ctrl_val ctrl_next
        asn1::parse_tlv "${remaining}" 0 ctrl_tag ctrl_len ctrl_val ctrl_next
        _ldap_mp_dict[controls]="${ctrl_val}"
    else
        _ldap_mp_dict[has_controls]="0"
    fi
}

# ── Utilitaires de résultat ───────────────────────────────────────────────────

# ldap::message::parse_ldapresult <hex_result> <var_dict_name>
#
# Parse une structure LDAPResult (commune à BindResponse, SearchResultDone, etc.) :
#   LDAPResult ::= SEQUENCE {
#       resultCode     ENUMERATED,
#       matchedDN      LDAPDN,
#       diagnosticMsg  LDAPString,
#       referral       [3] Referral OPTIONAL
#   }
ldap::message::parse_ldapresult() {
    local result="${1^^}"
    local -n _ldap_lrp_dict="$2"

    local -i off=0

    # resultCode ENUMERATED (tag 0x0A)
    local rc_tag rc_len rc_val rc_next
    asn1::parse_tlv "${result}" 0 rc_tag rc_len rc_val rc_next
    if [[ "${rc_tag}" != "0A" ]]; then
        log::error "ldap::message::parse_ldapresult : ENUMERATED attendu (0x0A), tag=0x${rc_tag}"
        return 1
    fi
    hex::to_int "${rc_val}" _ldap_lrp_dict[result_code]
    local rc_int="${_ldap_lrp_dict[result_code]}"
    _ldap_lrp_dict[result_name]="${LDAP_RC_NAMES[${rc_int}]:-unknown(${rc_int})}"

    # matchedDN OCTET STRING (tag 0x04)
    local dn_tag dn_len dn_val dn_next
    asn1::parse_tlv "${result}" "${rc_next}" dn_tag dn_len dn_val dn_next
    hex::to_string "${dn_val}" _ldap_lrp_dict[matched_dn]

    # diagnosticMessage OCTET STRING (tag 0x04)
    local diag_tag diag_len diag_val diag_next
    asn1::parse_tlv "${result}" "${dn_next}" diag_tag diag_len diag_val diag_next
    hex::to_string "${diag_val}" _ldap_lrp_dict[diagnostic_msg]
}

# ldap::message::rc_name <result_code_int>
#
# Retourne le nom lisible d'un ResultCode, ou "unknown(N)".
ldap::message::rc_name() {
    printf '%s' "${LDAP_RC_NAMES[${1}]:-unknown(${1})}"
}
