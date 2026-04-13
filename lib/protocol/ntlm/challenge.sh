#!/usr/bin/env bash
#
# lib/protocol/ntlm/challenge.sh — Message NTLM Challenge (Type 2)
#
# Le message Challenge est envoyé par le serveur en réponse au Negotiate.
# Il contient le challenge aléatoire 8 octets et les informations du serveur.
#
# Structure du message (MS-NLMP §2.2.1.2) :
#   Signature       : 8 octets  — "NTLMSSP\0"
#   MessageType     : 4 octets  — 0x00000002
#   TargetNameFields: 8 octets
#   NegotiateFlags  : 4 octets
#   ServerChallenge : 8 octets  — le nonce aléatoire
#   Reserved        : 8 octets
#   TargetInfoFields: 8 octets
#   Version         : 8 octets  — (optionnel)
#   Payload         : TargetName + TargetInfo
#
# Référence : MS-NLMP §2.2.1.2
#
# Dépendances : core/hex, core/bytes, core/endian, core/log, encoding/utf16, protocol/ntlm/flags
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_NTLM_CHALLENGE:-}" ]] && return 0
readonly _ENSH_PROTO_NTLM_CHALLENGE=1

ensh::import core/hex
ensh::import core/bytes
ensh::import core/endian
ensh::import core/log
ensh::import encoding/utf16
ensh::import protocol/ntlm/flags

# Signature NTLM (partagée avec negotiate.sh mais déclarée localement pour l'autonomie)
readonly _NTLM_CHALLENGE_SIG="4E544C4D53535000"

# ── Types de TargetInfo (MS-NLMP §2.2.2.1 MsvAvFlags) ────────────────────────

readonly NTLM_AVID_EOL=0               # Fin de la liste
readonly NTLM_AVID_NB_COMPUTER=1       # Nom NetBIOS de l'ordinateur
readonly NTLM_AVID_NB_DOMAIN=2         # Nom NetBIOS du domaine
readonly NTLM_AVID_DNS_COMPUTER=3      # FQDN de l'ordinateur
readonly NTLM_AVID_DNS_DOMAIN=4        # FQDN du domaine
readonly NTLM_AVID_DNS_TREE=5          # Nom DNS de la forêt
readonly NTLM_AVID_FLAGS=6             # Attributs (MsvAvFlags)
readonly NTLM_AVID_TIMESTAMP=7         # Timestamp FILETIME
readonly NTLM_AVID_SINGLE_HOST=8       # Données hôte unique
readonly NTLM_AVID_TARGET_NAME=9       # Nom de cible SPN
readonly NTLM_AVID_CHANNEL_BINDINGS=10

# ── Parsing ───────────────────────────────────────────────────────────────────

# ntlm::challenge::parse <hex_msg> <var_out_dict_name>
#
# Parse un message Challenge et remplit un tableau associatif avec :
#   flags          — NegotiateFlags (hex LE32)
#   server_challenge — 8 octets hex
#   target_name    — nom de la cible (hex UTF-16LE)
#   target_info    — bloc TargetInfo brut (hex)
#
# Exemple :
#   declare -A chall
#   ntlm::challenge::parse "${msg}" chall
#   echo "${chall[server_challenge]}"
ntlm::challenge::parse() {
    local msg="${1^^}"
    local -n _ntlm_chall_dict="$2"

    # Vérification signature
    if [[ "${msg:0:16}" != "${_NTLM_CHALLENGE_SIG}" ]]; then
        log::error "ntlm::challenge::parse : signature invalide"
        return 1
    fi

    # MessageType doit être 2
    local msgtype; endian::read_le32 "${msg}" 8 msgtype
    if (( msgtype != 2 )); then
        log::error "ntlm::challenge::parse : MessageType attendu 2, obtenu ${msgtype}"
        return 1
    fi

    # TargetNameFields (offset 12) : Len(2), MaxLen(2), Offset(4)
    local tn_len; endian::read_le16 "${msg}" 12 tn_len
    local tn_off; endian::read_le32 "${msg}" 16 tn_off

    # NegotiateFlags (offset 20)
    local flags; hex::slice "${msg}" 20 4 flags
    _ntlm_chall_dict[flags]="${flags}"

    # ServerChallenge (offset 24) — 8 octets
    local challenge; hex::slice "${msg}" 24 8 challenge
    _ntlm_chall_dict[server_challenge]="${challenge}"

    # Reserved (offset 32) — 8 octets ignorés

    # TargetInfoFields (offset 40) : Len(2), MaxLen(2), Offset(4)
    local ti_len; endian::read_le16 "${msg}" 40 ti_len
    local ti_off; endian::read_le32 "${msg}" 44 ti_off

    # Extraction du payload
    hex::slice "${msg}" "${tn_off}" "${tn_len}" _ntlm_chall_dict[target_name]
    hex::slice "${msg}" "${ti_off}" "${ti_len}" _ntlm_chall_dict[target_info]
}

# ntlm::challenge::parse_target_info <hex_target_info> <var_out_dict_name>
#
# Parse le bloc TargetInfo (liste de AvPair) et remplit un tableau associatif.
# Clés : nb_computer, nb_domain, dns_computer, dns_domain, dns_tree, timestamp
ntlm::challenge::parse_target_info() {
    local ti="${1^^}"
    local -n _ntlm_ti_dict="$2"

    local -i off=0
    local -i ti_len=$(( ${#ti} / 2 ))

    while (( off + 4 <= ti_len )); do
        local avid; endian::read_le16 "${ti}" "${off}" avid
        local avlen; endian::read_le16 "${ti}" "$(( off + 2 ))" avlen
        local avval; hex::slice "${ti}" "$(( off + 4 ))" "${avlen}" avval

        case "${avid}" in
            ${NTLM_AVID_EOL})           break ;;
            ${NTLM_AVID_NB_COMPUTER})   _ntlm_ti_dict[nb_computer]="${avval}" ;;
            ${NTLM_AVID_NB_DOMAIN})     _ntlm_ti_dict[nb_domain]="${avval}" ;;
            ${NTLM_AVID_DNS_COMPUTER})  _ntlm_ti_dict[dns_computer]="${avval}" ;;
            ${NTLM_AVID_DNS_DOMAIN})    _ntlm_ti_dict[dns_domain]="${avval}" ;;
            ${NTLM_AVID_DNS_TREE})      _ntlm_ti_dict[dns_tree]="${avval}" ;;
            ${NTLM_AVID_TIMESTAMP})     _ntlm_ti_dict[timestamp]="${avval}" ;;
            ${NTLM_AVID_FLAGS})         _ntlm_ti_dict[av_flags]="${avval}" ;;
        esac

        (( off += 4 + avlen ))
    done
}

# ntlm::challenge::target_info_inject_cifs_spn <target_info_hex> <var_out_hex>
#
# Réinsère une liste AvPair sans MsvAvTargetName (9), puis ajoute
#   MsvAvTargetName = UTF-16LE("cifs/") || MsvAvDnsComputerName
# avant MsvAvEOL. Aligné sur impacket (NTLM) pour les serveurs avec validation SPN
# (« Restrict NTLM » / cible SPN) — sinon SMB2 peut répondre ACCESS_DENIED aux requêtes
# signées (ex. TREE_CONNECT) malgré SESSION_SETUP SUCCESS.
ntlm::challenge::target_info_inject_cifs_spn() {
    local ti="${1^^}"
    local -n _ntlm_spn_ti_out="$2"

    if [[ -z "${ti}" ]]; then
        _ntlm_spn_ti_out=""
        return 0
    fi

    declare -A _spn_ti
    ntlm::challenge::parse_target_info "${ti}" _spn_ti || {
        _ntlm_spn_ti_out="${ti}"
        return 0
    }

    local dns_hex="${_spn_ti[dns_computer]:-}"
    [[ -z "${dns_hex}" ]] && dns_hex="${_spn_ti[nb_computer]:-}"
    if [[ -z "${dns_hex}" ]]; then
        _ntlm_spn_ti_out="${ti}"
        return 0
    fi

    local cifs_pre
    utf16::encode_le "cifs/" cifs_pre
    local spn_hex="${cifs_pre}${dns_hex}"
    local -i spn_b=$(( ${#spn_hex} / 2 ))

    local out="" _spn_off=0
    local -i _spn_ti_len=$(( ${#ti} / 2 ))
    while (( _spn_off + 4 <= _spn_ti_len )); do
        local -i _avid _avlen
        endian::read_le16 "${ti}" "${_spn_off}" _avid
        endian::read_le16 "${ti}" "$(( _spn_off + 2 ))" _avlen
        (( _avid == NTLM_AVID_EOL )) && break
        if (( _avid != NTLM_AVID_TARGET_NAME )); then
            local _v
            hex::slice "${ti}" "$(( _spn_off + 4 ))" "${_avlen}" _v
            local _idl _ll
            endian::le16 "${_avid}" _idl
            endian::le16 "${_avlen}" _ll
            out+="${_idl}${_ll}${_v}"
        fi
        (( _spn_off += 4 + _avlen ))
    done

    local _tn_id_le _tn_len_le
    endian::le16 "${NTLM_AVID_TARGET_NAME}" _tn_id_le
    endian::le16 "${spn_b}" _tn_len_le
    out+="${_tn_id_le}${_tn_len_le}${spn_hex}"
    out+="00000000"

    _ntlm_spn_ti_out="${out}"
    log::debug "ntlm::challenge : TargetInfo — MsvAvTargetName (cifs/ + DNS/NetBIOS) injecté"
    return 0
}

# ntlm::challenge::build_target_info <var_out> [nb_domain] [nb_computer] [dns_domain] [dns_computer] [timestamp_hex]
#
# Construit un bloc TargetInfo (pour les serveurs Ensh ou les tests).
ntlm::challenge::build_target_info() {
    local -n _ntlm_bti_out="$1"
    local nb_domain="${2:-}"
    local nb_computer="${3:-}"
    local dns_domain="${4:-}"
    local dns_computer="${5:-}"
    local timestamp="${6:-0000000000000000}"

    _ntlm_bti_out=""

    _ntlm_bti_build_avpair() {
        local -i id="$1"
        local val="$2"
        local -n _avp_out="$3"
        local id_le len_le
        endian::le16 "${id}" id_le
        endian::le16 "$(( ${#val} / 2 ))" len_le
        _avp_out="${id_le}${len_le}${val}"
    }

    local avp
    if [[ -n "${nb_domain}" ]]; then
        local hex_nb_domain; hex::from_string "${nb_domain}" hex_nb_domain
        # Note : dans un vrai contexte, ces champs sont en UTF-16LE
        _ntlm_bti_build_avpair "${NTLM_AVID_NB_DOMAIN}" "${hex_nb_domain}" avp
        _ntlm_bti_out+="${avp}"
    fi

    if [[ -n "${nb_computer}" ]]; then
        local hex_nb_comp; hex::from_string "${nb_computer}" hex_nb_comp
        _ntlm_bti_build_avpair "${NTLM_AVID_NB_COMPUTER}" "${hex_nb_comp}" avp
        _ntlm_bti_out+="${avp}"
    fi

    if [[ -n "${dns_domain}" ]]; then
        local hex_dns_dom; hex::from_string "${dns_domain}" hex_dns_dom
        _ntlm_bti_build_avpair "${NTLM_AVID_DNS_DOMAIN}" "${hex_dns_dom}" avp
        _ntlm_bti_out+="${avp}"
    fi

    if [[ -n "${dns_computer}" ]]; then
        local hex_dns_comp; hex::from_string "${dns_computer}" hex_dns_comp
        _ntlm_bti_build_avpair "${NTLM_AVID_DNS_COMPUTER}" "${hex_dns_comp}" avp
        _ntlm_bti_out+="${avp}"
    fi

    # Timestamp
    _ntlm_bti_build_avpair "${NTLM_AVID_TIMESTAMP}" "${timestamp}" avp
    _ntlm_bti_out+="${avp}"

    # EOL
    _ntlm_bti_out+="00000000"
}
