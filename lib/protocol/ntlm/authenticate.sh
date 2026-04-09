#!/usr/bin/env bash
#
# lib/protocol/ntlm/authenticate.sh — Message NTLM Authenticate (Type 3)
#
# Le message Authenticate est le troisième et dernier message de l'échange.
# Le client y inclut sa réponse au challenge du serveur.
#
# Structure du message (MS-NLMP §2.2.1.3) :
#   Signature            : 8 octets
#   MessageType          : 4 octets — 0x00000003
#   LmChallengeResponseFields  : 8 octets
#   NtChallengeResponseFields  : 8 octets
#   DomainNameFields     : 8 octets
#   UserNameFields       : 8 octets
#   WorkstationFields    : 8 octets
#   EncryptedRandomSessionKey  : 8 octets (optionnel)
#   NegotiateFlags       : 4 octets
#   Version              : 8 octets
#   MIC                  : 16 octets (optionnel)
#   Payload              : LmResp + NtResp + Domain + User + Workstation + SessionKey
#
# Référence : MS-NLMP §2.2.1.3, §3.3.2 (NTLMv2)
#
# Dépendances : core/hex, core/bytes, core/endian, core/log,
#               crypto/nt_hash, crypto/hmac_md5,
#               encoding/utf16, protocol/ntlm/flags
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_PROTO_NTLM_AUTHENTICATE:-}" ]] && return 0
readonly _ENSH_PROTO_NTLM_AUTHENTICATE=1

ensh::import core/hex
ensh::import core/bytes
ensh::import core/endian
ensh::import core/log
ensh::import crypto/nt_hash
ensh::import crypto/hmac_md5
ensh::import encoding/utf16
ensh::import protocol/ntlm/flags

readonly _NTLM_AUTH_SIG="4E544C4D53535000"

# ── NTLMv2 — Calcul de la réponse ────────────────────────────────────────────

# ntlm::auth::compute_ntv2_response <nt_hash_hex> <username> <domain>
#                                   <server_challenge_hex> <client_challenge_hex>
#                                   <target_info_hex> <timestamp_hex>
#                                   <var_nt_proof_out> <var_blob_out>
#
# Calcule la réponse NTLMv2 complète :
#   1. NT hash du mot de passe  → ResponseKeyNT = HMAC-MD5(NT_HASH, upper(user)||domain)
#   2. Client blob (NTLMv2ClientChallenge)
#   3. NT-Proof-String = HMAC-MD5(ResponseKeyNT, ServerChallenge || Blob)
#   4. NtChallengeResponse = NT-Proof-String || Blob
ntlm::auth::compute_ntv2_response() {
    local nt_hash="$1"
    local username="$2"
    local domain="$3"
    local server_challenge="$4"
    local client_challenge="$5"
    local target_info="$6"
    local timestamp="${7:-}"
    local -n _ntlm_ntv2_proof="$8"
    local -n _ntlm_ntv2_blob="$9"

    # Si pas de timestamp, utiliser l'heure courante en FILETIME
    # FILETIME = nanosecondes depuis 01/01/1601, divisées par 100
    # ≈ epoch_unix * 10^7 + 116444736000000000
    if [[ -z "${timestamp}" ]]; then
        local -i epoch_s; epoch_s="$(date +%s)"
        local -i filetime=$(( epoch_s * 10000000 + 116444736000000000 ))
        endian::le64 0 "${filetime}" timestamp
    fi

    # ── ResponseKeyNT = HMAC-MD5(NT_hash, uppercase(username) || domain) en UTF-16LE
    local user_upper="${username^^}"
    local user_domain_utf16
    local user_utf16 domain_utf16
    utf16::encode_le "${user_upper}" user_utf16
    utf16::encode_le "${domain}" domain_utf16
    user_domain_utf16="${user_utf16}${domain_utf16}"

    local response_key_nt
    hmac_md5::compute "${nt_hash}" "${user_domain_utf16}" response_key_nt

    log::debug "ntlm::auth : ResponseKeyNT = ${response_key_nt}"

    # ── NTLMv2 Client Blob (NTLMv2ClientChallenge) ─────────────────────────────
    # Structure :
    #   RespType       : 01
    #   HiRespType     : 01
    #   Reserved1      : 0000
    #   Reserved2      : 00000000
    #   TimeStamp      : 8 octets LE FILETIME
    #   ChallengeFromClient : 8 octets (client challenge)
    #   Reserved3      : 00000000
    #   TargetInfo     : variable
    #   Reserved4      : 00000000
    local blob=""
    blob+="01"                      # RespType
    blob+="01"                      # HiRespType
    blob+="0000"                    # Reserved1
    blob+="00000000"                # Reserved2
    blob+="${timestamp}"            # TimeStamp (8 octets)
    blob+="${client_challenge}"     # ChallengeFromClient
    blob+="00000000"                # Reserved3
    blob+="${target_info}"          # TargetInfo
    blob+="00000000"                # Reserved4

    _ntlm_ntv2_blob="${blob}"

    # ── NT-Proof-String = HMAC-MD5(ResponseKeyNT, ServerChallenge || Blob) ────
    hmac_md5::compute "${response_key_nt}" "${server_challenge}${blob}" _ntlm_ntv2_proof

    log::debug "ntlm::auth : NT-Proof-String = ${_ntlm_ntv2_proof}"
}

# ── Construction du message Authenticate ────────────────────────────────────

# ntlm::authenticate::build <var_out>
#                           <username> <domain> <workstation>
#                           <nt_hash_hex>
#                           <server_challenge_hex>
#                           <target_info_hex>
#                           [flags_hex] [client_challenge_hex] [timestamp_hex]
#
# Construit un message NTLM Authenticate (NTLMv2).
#
# Exemple :
#   ntlm::authenticate::build msg \
#       "Administrator" "CORP" "WORKSTATION" \
#       "$(nt_hash::from_password 'Password'; ...)" \
#       "${server_challenge}" "${target_info}"
ntlm::authenticate::build() {
    local -n _ntlm_auth_out="$1"
    local username="$2"
    local domain="$3"
    local workstation="$4"
    local nt_hash="$5"
    local server_challenge="$6"
    local target_info="$7"
    local flags_hex="${8:-}"
    local client_challenge="${9:-}"
    local timestamp="${10:-}"

    # Flags par défaut
    if [[ -z "${flags_hex}" ]]; then
        ntlm::flags::default_negotiate flags_hex
    fi

    # Générer un client challenge aléatoire si absent
    if [[ -z "${client_challenge}" ]]; then
        # 8 octets pseudo-aléatoires via /dev/urandom ou RANDOM
        if [[ -r /dev/urandom ]]; then
            client_challenge="$(dd if=/dev/urandom bs=8 count=1 2>/dev/null | xxd -p | tr -d '\n')"
            client_challenge="${client_challenge^^:0:16}"
        else
            printf -v client_challenge '%04X%04X%04X%04X' \
                "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}"
        fi
    fi

    # Calculer la réponse NTLMv2
    local nt_proof ntv2_blob
    ntlm::auth::compute_ntv2_response \
        "${nt_hash}" "${username}" "${domain}" \
        "${server_challenge}" "${client_challenge}" \
        "${target_info}" "${timestamp}" \
        nt_proof ntv2_blob

    local nt_response="${nt_proof}${ntv2_blob}"

    # LM response : pour NTLMv2 c'est client_challenge || 00*16
    local lm_response="${client_challenge}0000000000000000"

    # Encoder les champs texte en UTF-16LE
    local domain_utf16 username_utf16 workstation_utf16
    utf16::encode_le "${domain}"      domain_utf16
    utf16::encode_le "${username}"    username_utf16
    utf16::encode_le "${workstation}" workstation_utf16

    # Tailles
    local -i lm_len=$(( ${#lm_response} / 2 ))
    local -i nt_len=$(( ${#nt_response} / 2 ))
    local -i dom_len=$(( ${#domain_utf16} / 2 ))
    local -i usr_len=$(( ${#username_utf16} / 2 ))
    local -i ws_len=$(( ${#workstation_utf16} / 2 ))

    # Calcul des offsets (header = 72 octets avec Version, sans MIC pour simplifier)
    local -i base_offset=72
    local -i lm_off="${base_offset}"
    local -i nt_off=$(( lm_off + lm_len ))
    local -i dom_off=$(( nt_off + nt_len ))
    local -i usr_off=$(( dom_off + dom_len ))
    local -i ws_off=$(( usr_off + usr_len ))

    # ── Assembler le message ──────────────────────────────────────────────────
    local buf="${_NTLM_AUTH_SIG}"       # Signature (8 octets)

    local msgtype; endian::le32 3 msgtype
    buf+="${msgtype}"                   # MessageType = 3 (4 octets)

    # Fonction helper pour un champ FieldsHeader(Len, MaxLen, Offset)
    _ntlm_field() {
        local -i l="$1" o="$2"
        local lh oh
        endian::le16 "${l}" lh
        endian::le32 "${o}" oh
        printf '%s%s%s' "${lh}" "${lh}" "${oh}"
    }

    buf+="$(_ntlm_field "${lm_len}"  "${lm_off}")"   # LmChallengeResponseFields
    buf+="$(_ntlm_field "${nt_len}"  "${nt_off}")"    # NtChallengeResponseFields
    buf+="$(_ntlm_field "${dom_len}" "${dom_off}")"   # DomainNameFields
    buf+="$(_ntlm_field "${usr_len}" "${usr_off}")"   # UserNameFields
    buf+="$(_ntlm_field "${ws_len}"  "${ws_off}")"    # WorkstationFields

    # EncryptedRandomSessionKey — vide pour l'instant
    buf+="00000000" buf+="0000"  # Len=0, MaxLen=0, Offset=0
    local esk_off; endian::le32 "$(( ws_off + ws_len ))" esk_off
    # Correction : les 8 derniers octets ajoutés ci-dessus sont incorrects.
    # On retire et réécrit correctement :
    buf="${buf:0:$(( ${#buf} - 12 ))}"
    buf+="0000000000000000"              # SessionKey fields vides (8 octets)

    buf+="${flags_hex}"                 # NegotiateFlags (4 octets)

    # Version : Windows 10.0.19041 Rev 15
    buf+="0A00414B0000000F"             # Version (8 octets)

    # ── Payload ───────────────────────────────────────────────────────────────
    buf+="${lm_response}"
    buf+="${nt_response}"
    buf+="${domain_utf16}"
    buf+="${username_utf16}"
    buf+="${workstation_utf16}"

    _ntlm_auth_out="${buf^^}"
}

# ntlm::authenticate::parse <hex_msg> <var_out_dict>
#
# Parse un message Authenticate et extrait les champs principaux.
ntlm::authenticate::parse() {
    local msg="${1^^}"
    local -n _ntlm_ap_dict="$2"

    if [[ "${msg:0:16}" != "${_NTLM_AUTH_SIG}" ]]; then
        log::error "ntlm::authenticate::parse : signature invalide"
        return 1
    fi

    local msgtype; endian::read_le32 "${msg}" 8 msgtype
    (( msgtype != 3 )) && { log::error "ntlm::authenticate::parse : MessageType attendu 3"; return 1; }

    local lm_len lm_off nt_len nt_off dom_len dom_off usr_len usr_off ws_len ws_off
    endian::read_le16 "${msg}" 12 lm_len
    endian::read_le32 "${msg}" 16 lm_off
    endian::read_le16 "${msg}" 20 nt_len
    endian::read_le32 "${msg}" 24 nt_off
    endian::read_le16 "${msg}" 28 dom_len
    endian::read_le32 "${msg}" 32 dom_off
    endian::read_le16 "${msg}" 36 usr_len
    endian::read_le32 "${msg}" 40 usr_off
    endian::read_le16 "${msg}" 44 ws_len
    endian::read_le32 "${msg}" 48 ws_off

    hex::slice "${msg}" "${lm_off}"  "${lm_len}"  _ntlm_ap_dict[lm_response]
    hex::slice "${msg}" "${nt_off}"  "${nt_len}"  _ntlm_ap_dict[nt_response]
    hex::slice "${msg}" "${dom_off}" "${dom_len}" _ntlm_ap_dict[domain]
    hex::slice "${msg}" "${usr_off}" "${usr_len}" _ntlm_ap_dict[username]
    hex::slice "${msg}" "${ws_off}"  "${ws_len}"  _ntlm_ap_dict[workstation]

    # Flags à l'offset 60
    hex::slice "${msg}" 60 4 _ntlm_ap_dict[flags]

    # NT-Proof-String = premiers 16 octets de nt_response
    _ntlm_ap_dict[nt_proof]="${_ntlm_ap_dict[nt_response]:0:32}"

    # Blob = nt_response sans les 16 premiers octets
    _ntlm_ap_dict[nt_blob]="${_ntlm_ap_dict[nt_response]:32}"
}
