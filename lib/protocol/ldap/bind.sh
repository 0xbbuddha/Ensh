#!/usr/bin/env bash
#
# lib/protocol/ldap/bind.sh — BindRequest et BindResponse LDAP
#
# Le Bind est l'opération d'authentification LDAP. Trois mécanismes :
#
#   1. Simple Bind : DN + mot de passe en clair (sur TLS uniquement en prod)
#   2. SASL/NTLM  : échange NTLM encapsulé dans SASL (GSS-SPNEGO)
#   3. Anonymous  : DN et mot de passe vides
#
# Structure BindRequest (RFC 4511 §4.2) :
#   BindRequest ::= [APPLICATION 0] SEQUENCE {
#       version         INTEGER (1..127),
#       name            LDAPDN,
#       authentication  AuthenticationChoice
#   }
#   AuthenticationChoice ::= CHOICE {
#       simple          [0] OCTET STRING,
#       sasl            [3] SaslCredentials
#   }
#   SaslCredentials ::= SEQUENCE {
#       mechanism   LDAPString,
#       credentials OCTET STRING OPTIONAL
#   }
#
# Référence : RFC 4511 §4.2
#
# Dépendances : core/hex, encoding/asn1, protocol/ldap/message
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_LDAP_BIND:-}" ]] && return 0
readonly _ENSH_PROTO_LDAP_BIND=1

ensh::import core/hex
ensh::import core/log
ensh::import encoding/asn1
ensh::import protocol/ldap/message

# ── BindRequest ───────────────────────────────────────────────────────────────

# ldap::bind::simple <dn> <password> <var_out>
#
# Construit une BindRequest avec authentification simple.
# Non encapsulée dans LDAPMessage — utiliser ldap::message::wrap.
#
# Exemple :
#   ldap::bind::simple "cn=admin,dc=corp,dc=local" "P@ssw0rd" req
#   ldap::message::wrap 1 "${req}" msg
ldap::bind::simple() {
    local dn="$1"
    local password="$2"
    local -n _ldap_bs_out="$3"

    # version INTEGER = 3
    local ver_hex
    asn1::integer "03" ver_hex

    # name LDAPDN (OCTET STRING)
    local dn_hex
    hex::from_string "${dn}" dn_hex
    local dn_os
    asn1::octet_string "${dn_hex}" dn_os

    # authentication [0] simple = OCTET STRING avec tag contextuel primitif
    local pw_hex
    hex::from_string "${password}" pw_hex
    local pw_tlv
    asn1::tlv "80" "${pw_hex}" pw_tlv

    # BindRequest [APPLICATION 0] = 0x60
    local content="${ver_hex}${dn_os}${pw_tlv}"
    asn1::tlv "60" "${content}" _ldap_bs_out
}

# ldap::bind::anonymous <var_out>
#
# Construit une BindRequest anonyme (DN vide, mot de passe vide).
ldap::bind::anonymous() {
    ldap::bind::simple "" "" "$1"
}

# ldap::bind::sasl <mechanism> <var_out> [credentials_hex]
#
# Construit une BindRequest SASL.
# <mechanism> : ex: "GSS-SPNEGO", "NTLM", "GSSAPI"
# <credentials_hex> : token SASL initial (optionnel pour le premier message)
#
# Utilisé pour l'authentification NTLM / Kerberos sur LDAP.
ldap::bind::sasl() {
    local mechanism="$1"
    local -n _ldap_sasl_out="$2"
    local credentials="${3:-}"

    # version = 3
    local ver_hex
    asn1::integer "03" ver_hex

    # name LDAPDN vide (authentication SASL n'utilise pas le DN)
    local dn_os
    asn1::octet_string "" dn_os

    # SaslCredentials ::= SEQUENCE { mechanism LDAPString, credentials OPTIONAL }
    local mech_hex
    hex::from_string "${mechanism}" mech_hex
    local mech_os
    asn1::octet_string "${mech_hex}" mech_os

    local sasl_content="${mech_os}"
    if [[ -n "${credentials}" ]]; then
        local cred_os
        asn1::octet_string "${credentials^^}" cred_os
        sasl_content+="${cred_os}"
    fi

    local sasl_seq
    asn1::sequence "${sasl_content}" sasl_seq

    # authentication [3] = tag contextuel construit 0xA3
    local auth_tlv
    asn1::tlv "A3" "${sasl_seq}" auth_tlv

    local content="${ver_hex}${dn_os}${auth_tlv}"
    asn1::tlv "60" "${content}" _ldap_sasl_out
}

# ── BindResponse ──────────────────────────────────────────────────────────────

# ldap::bind::parse_response <op_value_hex> <var_dict_name>
#
# Parse la valeur d'un BindResponse (la partie après le tag APPLICATION 1).
#
# Remplit le dict avec :
#   result_code     — entier
#   result_name     — chaîne lisible
#   matched_dn
#   diagnostic_msg
#   server_creds    — crédentiels SASL du serveur (hex, si présents)
ldap::bind::parse_response() {
    local op_val="${1^^}"
    local -n _ldap_bpr_dict="$2"

    # Tenter de parser comme LDAPResult directement
    ldap::message::parse_ldapresult "${op_val}" _ldap_bpr_dict || return 1

    # serverSaslCreds [7] OPTIONAL (tag 0x87) — présent dans les échanges SASL multi-étapes
    local rc_next
    # Calculer l'offset après les 3 champs LDAPResult
    local tag1 len1 val1 next1
    asn1::parse_tlv "${op_val}" 0 tag1 len1 val1 next1
    local tag2 len2 val2 next2
    asn1::parse_tlv "${op_val}" "${next1}" tag2 len2 val2 next2
    local tag3 len3 val3 next3
    asn1::parse_tlv "${op_val}" "${next2}" tag3 len3 val3 next3

    # Vérifier s'il y a un champ sasl credentials [7]
    local remaining="${op_val:$(( next3 * 2 ))}"
    if [[ -n "${remaining}" ]] && [[ "${remaining:0:2}" == "87" ]]; then
        local sc_tag sc_len sc_val sc_next
        asn1::parse_tlv "${remaining}" 0 sc_tag sc_len sc_val sc_next
        _ldap_bpr_dict[server_creds]="${sc_val}"
    fi
}

# ldap::bind::is_success <var_dict_name>
#
# Retourne 0 si le BindResponse indique un succès (resultCode = 0).
ldap::bind::is_success() {
    local -n _ldap_bsuc_dict="$1"
    [[ "${_ldap_bsuc_dict[result_code]}" == "0" ]]
}

# ldap::bind::needs_sasl_continue <var_dict_name>
#
# Retourne 0 si le serveur indique qu'il faut continuer l'échange SASL
# (resultCode = 14 = saslBindInProgress).
ldap::bind::needs_sasl_continue() {
    local -n _ldap_bnsc_dict="$1"
    [[ "${_ldap_bnsc_dict[result_code]}" == "14" ]]
}
