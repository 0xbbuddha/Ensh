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
ensh::import crypto/rc4
ensh::import encoding/utf16
ensh::import protocol/ntlm/challenge
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
# ntlm::auth::compute_ntv2_response <nt_hash_hex> <username> <domain>
#                                   <server_challenge_hex> <client_challenge_hex>
#                                   <target_info_hex> <timestamp_hex>
#                                   <var_nt_proof_out> <var_blob_out>
#                                   [var_response_key_nt_out]
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
    local _ntlm_ntv2_rknt_varname="${10:-}"

    # Si pas de timestamp, utiliser l'heure courante en FILETIME
    # FILETIME = nanosecondes depuis 01/01/1601, divisées par 100
    # ≈ epoch_unix * 10^7 + 116444736000000000
    if [[ -z "${timestamp}" ]]; then
        local -i epoch_s; epoch_s="$(date +%s)"
        local -i filetime=$(( epoch_s * 10000000 + 116444736000000000 ))
        local -i ft_hi=$(( filetime >> 32 ))
        local -i ft_lo=$(( filetime & 0xFFFFFFFF ))
        endian::le64 "${ft_hi}" "${ft_lo}" timestamp
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

    # Exporter ResponseKeyNT si demandé (nécessaire pour SessionBaseKey)
    if [[ -n "${_ntlm_ntv2_rknt_varname}" ]]; then
        local -n _ntlm_ntv2_rknt_out="${_ntlm_ntv2_rknt_varname}"
        _ntlm_ntv2_rknt_out="${response_key_nt}"
    fi
}

# ── Construction du message Authenticate ────────────────────────────────────

# ntlm::authenticate::build <var_out>
#                           <username> <domain> <workstation>
#                           <nt_hash_hex>
#                           <server_challenge_hex>
#                           <target_info_hex>
#                           [flags_hex] [client_challenge_hex] [timestamp_hex]
#                           [var_exported_session_key_out]
#                           [negotiate_msg_hex] [challenge_msg_hex]
#
# Construit un message NTLM Authenticate (NTLMv2).
# Si NEGOTIATE_VERSION : champ Version (8 o) + MIC (16 o) après les flags ; MIC requis par MS-NLMP
# lorsque TargetInfo est présent dans le Challenge (SMB domaine) :
#   MIC = HMAC-MD5(SessionBaseKey, Type1 || Type2 || Type3_avec_MIC_à_zéro).
# Les messages Type 1 et 2 bruts doivent être passés en args 12 et 13.
# Si KEY_EXCH est actif dans les flags, calcule et inclut l'EncryptedRandomSessionKey.
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
    local _ntlm_esk_varname="${11:-}"
    local negotiate_hex="${12:-}"
    local challenge_hex="${13:-}"

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

    # MsvAvTargetName = cifs/<FQDN> : requis sur certains DC (validation SPN / NTLM)
    # — cf. impacket ntlm.py (sinon ACCESS_DENIED SMB2 signé après auth réussie).
    if [[ -n "${target_info}" ]]; then
        local _ti_spn_fixed
        ntlm::challenge::target_info_inject_cifs_spn "${target_info}" _ti_spn_fixed
        target_info="${_ti_spn_fixed}"
    fi

    # Réutiliser l'horodatage du serveur si présent dans TargetInfo, comme impacket.
    if [[ -z "${timestamp}" && -n "${target_info}" ]]; then
        local -A _auth_ti
        ntlm::challenge::parse_target_info "${target_info}" _auth_ti || true
        if [[ -n "${_auth_ti[timestamp]:-}" ]]; then
            timestamp="${_auth_ti[timestamp]}"
        fi
    fi

    # Calculer la réponse NTLMv2 + récupérer ResponseKeyNT pour SessionBaseKey
    local nt_proof ntv2_blob _response_key_nt
    ntlm::auth::compute_ntv2_response \
        "${nt_hash}" "${username}" "${domain}" \
        "${server_challenge}" "${client_challenge}" \
        "${target_info}" "${timestamp}" \
        nt_proof ntv2_blob _response_key_nt

    local nt_response="${nt_proof}${ntv2_blob}"

    # LMv2 response = HMAC(ResponseKeyNT, ServerChallenge || ClientChallenge) || ClientChallenge
    local lm_v2_proof lm_response
    hmac_md5::compute "${_response_key_nt}" "${server_challenge}${client_challenge}" lm_v2_proof
    lm_response="${lm_v2_proof}${client_challenge}"

    # SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr) — MIC + KEY_EXCH (MS-NLMP §3.4.5.1)
    local exported_session_key="" encrypted_session_key="" session_base_key=""
    hmac_md5::compute "${_response_key_nt}" "${nt_proof}" session_base_key

    local -i _has_key_exch=0
    local _flags_int; ntlm::flags::from_le32 "${flags_hex}" _flags_int
    (( _flags_int & NTLM_FL_KEY_EXCH )) && _has_key_exch=1

    local -i _has_ver=0
    (( _flags_int & NTLM_FL_VERSION )) && _has_ver=1

    local -i _need_mic=0
    if (( _has_ver )) && [[ -n "${target_info}" && -n "${negotiate_hex}" && -n "${challenge_hex}" ]]; then
        _need_mic=1
    fi

    # ── KEY_EXCH : ExportedSessionKey + EncryptedRandomSessionKey ─
    if (( _has_key_exch )); then

        # Générer ExportedSessionKey aléatoire (16 octets)
        if [[ -r /dev/urandom ]]; then
            exported_session_key="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p | tr -d '\n')"
            exported_session_key="${exported_session_key^^:0:32}"
        else
            printf -v exported_session_key '%04X%04X%04X%04X%04X%04X%04X%04X' \
                "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}" \
                "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}"
        fi

        # EncryptedRandomSessionKey = RC4(SessionBaseKey, ExportedSessionKey)
        rc4::crypt "${session_base_key}" "${exported_session_key}" encrypted_session_key

        log::debug "ntlm::auth : SessionBaseKey=${session_base_key}"
        log::debug "ntlm::auth : ExportedSessionKey=${exported_session_key}"
        log::debug "ntlm::auth : EncryptedSessionKey=${encrypted_session_key}"
    fi

    # Exporter ExportedSessionKey si demandé
    if [[ -n "${_ntlm_esk_varname}" ]]; then
        local -n _ntlm_esk_out="${_ntlm_esk_varname}"
        _ntlm_esk_out="${exported_session_key}"
    fi

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
    local -i esk_len=0
    (( _has_key_exch )) && esk_len=16

    # Début des blobs : 64 + (8 Version + 16 MIC si VERSION)
    local -i base_offset=64
    (( _has_ver )) && base_offset=88
    local -i lm_off="${base_offset}"
    local -i nt_off=$(( lm_off + lm_len ))
    local -i dom_off=$(( nt_off + nt_len ))
    local -i usr_off=$(( dom_off + dom_len ))
    local -i ws_off=$(( usr_off + usr_len ))
    local -i esk_off=$(( ws_off + ws_len ))

    # ── Assembler le message ──────────────────────────────────────────────────
    local buf="${_NTLM_AUTH_SIG}"

    local msgtype; endian::le32 3 msgtype
    buf+="${msgtype}"

    _ntlm_field() {
        local -i l="$1" o="$2"
        local lh oh
        endian::le16 "${l}" lh
        endian::le32 "${o}" oh
        printf '%s%s%s' "${lh}" "${lh}" "${oh}"
    }

    buf+="$(_ntlm_field "${lm_len}"  "${lm_off}")"
    buf+="$(_ntlm_field "${nt_len}"  "${nt_off}")"
    buf+="$(_ntlm_field "${dom_len}" "${dom_off}")"
    buf+="$(_ntlm_field "${usr_len}" "${usr_off}")"
    buf+="$(_ntlm_field "${ws_len}"  "${ws_off}")"
    buf+="$(_ntlm_field "${esk_len}" "${esk_off}")"   # EncryptedRandomSessionKey

    buf+="${flags_hex}"                 # NegotiateFlags
    if (( _has_ver )); then
        buf+="0A00414B0000000F"         # Version
        buf+="00000000000000000000000000000000"  # MIC (calculé si _need_mic)
    fi

    # ── Payload ───────────────────────────────────────────────────────────────
    buf+="${lm_response}"
    buf+="${nt_response}"
    buf+="${domain_utf16}"
    buf+="${username_utf16}"
    buf+="${workstation_utf16}"
    (( _has_key_exch )) && buf+="${encrypted_session_key}"

    buf="${buf^^}"

    if (( _need_mic )); then
        local _concat="${negotiate_hex^^}${challenge_hex^^}${buf}"
        local _mic
        hmac_md5::compute "${session_base_key}" "${_concat}" _mic || return 1
        # MIC à l’offset 68 (16 o) : 60 o d’en-tête + 8 o Version → 136 nibbles
        buf="${buf:0:136}${_mic:0:32}${buf:168}"
        log::debug "ntlm::auth : MIC OK (${_mic:0:8}...)"
    fi

    _ntlm_auth_out="${buf}"
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
