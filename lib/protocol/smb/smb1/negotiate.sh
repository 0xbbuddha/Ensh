#!/usr/bin/env bash
#
# lib/protocol/smb/smb1/negotiate.sh — SMB_COM_NEGOTIATE (commande 0x72)
#
# Le Negotiate est le premier échange SMB. Le client liste les dialectes
# qu'il supporte. Le serveur choisit le meilleur et répond avec ses capacités.
#
# Requête (WordCount=0) :
#   [SMB header]
#   WordCount : 0x00
#   ByteCount : LE16 (taille des dialectes)
#   Dialects  : répétition de {0x02, nom_ascii, 0x00}
#
# Réponse en mode Extended Security (WordCount=17, Capabilities & 0x80000000) :
#   [SMB header]
#   WordCount        : 0x11
#   DialectIndex     : LE16  — index du dialecte choisi
#   SecurityMode     : 1 octet
#   MaxMpxCount      : LE16
#   MaxNumberVcs     : LE16
#   MaxBufferSize    : LE32
#   MaxRawSize       : LE32
#   SessionKey       : LE32
#   Capabilities     : LE32
#   SystemTime       : 8 octets FILETIME
#   ServerTimeZone   : LE16
#   ChallengeLength  : 1 octet (0 si extended security)
#   ByteCount        : LE16
#   ServerGUID       : 16 octets
#   SecurityBlob     : SPNEGO NegTokenInit (reste du ByteCount - 16)
#
# Dépendances : core/endian, core/log, protocol/smb/smb1/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB1_NEGOTIATE:-}" ]] && return 0
readonly _ENSH_SMB1_NEGOTIATE=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb1/header

# ── Construction de la requête ────────────────────────────────────────────────

# smb1::negotiate::build_request <var_out> [pid]
#
# Construit un SMB_COM_NEGOTIATE complet avec multi-dialectes :
#   "NT LM 0.12"   → SMB1
#   "SMB 2.002"    → SMB2.0
#   "SMB 2.???"    → SMB2.x (wildcard — serveur choisit la meilleure version)
#
# Cette liste permet d'atteindre aussi bien les serveurs SMB1 que SMB2/3.
# Si le serveur répond avec FE534D42, c'est une réponse SMB2.
smb1::negotiate::build_request() {
    local -n _smb1_neg_req_out="$1"
    local -i pid="${2:-1234}"

    # ── En-tête SMB ──────────────────────────────────────────────────────────
    local hdr
    smb1::header::build hdr \
        "${SMB1_CMD_NEGOTIATE}" \
        0 "${pid}" 0 1  \
        "${SMB1_DEFAULT_FLAGS}" "${SMB1_DEFAULT_FLAGS2}"

    # ── Corps : dialectes ────────────────────────────────────────────────────
    # Format : pour chaque dialecte → 02 | ASCII | 00
    local dialects=""
    local _d _dh
    for _d in "NT LM 0.12" "SMB 2.002" "SMB 2.???"; do
        hex::from_string "${_d}" _dh
        dialects+="02${_dh}00"
    done
    local -i dlen=$(( ${#dialects} / 2 ))

    local wc="00"
    local bc_le; endian::le16 "${dlen}" bc_le

    local smb="${hdr}${wc}${bc_le}${dialects}"

    smb1::nbt_wrap "${smb}" _smb1_neg_req_out
    log::debug "smb1::negotiate : requête multi-dialectes prête (${dlen} octets)"
}

# ── Parsing de la réponse ─────────────────────────────────────────────────────

# smb1::negotiate::parse_response <hex_msg> <var_dict_out>
#
# Parse une réponse SMB_COM_NEGOTIATE (après retrait du framing NBT).
# Remplit le tableau associatif avec :
#   status          — NT Status (décimal)
#   uid             — User ID (toujours 0 au Negotiate)
#   dialect_index   — index du dialecte choisi
#   security_mode   — octet SecurityMode
#   max_buffer      — MaxBufferSize
#   capabilities    — Capabilities (décimal)
#   session_key     — SessionKey (hex LE32)
#   ext_sec         — "1" si extended security, "0" sinon
#   server_guid     — GUID serveur (hex 16 octets, si ext_sec=1)
#   spnego_blob     — blob SPNEGO du serveur (hex, si ext_sec=1)
#   challenge       — challenge NTLM direct (hex 8 octets, si ext_sec=0)
#
# Retourne 1 si erreur de parsing.
smb1::negotiate::parse_response() {
    local msg="${1^^}"
    local -n _smb1_neg_resp_dict="$2"

    # ── En-tête SMB ──────────────────────────────────────────────────────────
    local -A _hdr
    smb1::header::parse "${msg}" _hdr || return 1

    _smb1_neg_resp_dict[status]="${_hdr[status]}"
    _smb1_neg_resp_dict[uid]="${_hdr[uid]}"

    if (( _hdr[cmd] != SMB1_CMD_NEGOTIATE )); then
        log::error "smb1::negotiate::parse_response : commande inattendue 0x$(printf '%02X' ${_hdr[cmd]})"
        return 1
    fi

    # ── WordCount ─────────────────────────────────────────────────────────────
    # Offset 32 (en octets) → nibble 64
    local -i wc=$(( 16#${msg:64:2} ))

    if (( wc != 17 )); then
        log::warn "smb1::negotiate::parse_response : WordCount=${wc} (attendu 17 pour NT LM 0.12)"
    fi

    # ── Words (17 mots = 34 octets à partir de l'offset 33) ──────────────────
    # Offset byte 33 → nibble offset 66

    endian::read_le16 "${msg}" 33 _smb1_neg_resp_dict[dialect_index]

    _smb1_neg_resp_dict[security_mode]="$(( 16#${msg:70:2} ))"  # byte 35

    endian::read_le16 "${msg}" 36  _smb1_neg_resp_dict[max_mpx]
    endian::read_le32 "${msg}" 40  _smb1_neg_resp_dict[max_buffer]
    endian::read_le32 "${msg}" 48  _smb1_neg_resp_dict[session_key]
    endian::read_le32 "${msg}" 52  _smb1_neg_resp_dict[capabilities]

    # SystemTime (byte 56, 8 octets) et ServerTimeZone (byte 64)
    hex::slice "${msg}" 56 8 _smb1_neg_resp_dict[system_time]
    endian::read_le16 "${msg}" 64  _smb1_neg_resp_dict[tz]

    local -i chal_len=$(( 16#${msg:132:2} ))  # byte 66, ChallengeLength

    # ByteCount (byte 67-68)
    local -i bc
    endian::read_le16 "${msg}" 67 bc

    # ── Extended Security ? ───────────────────────────────────────────────────
    local -i caps="${_smb1_neg_resp_dict[capabilities]}"
    if (( (caps & SMB1_CAP_EXTENDED_SECURITY) != 0 )); then
        _smb1_neg_resp_dict[ext_sec]="1"

        # byte 69 → nibble 138 : ServerGUID (16 octets)
        hex::slice "${msg}" 69 16 _smb1_neg_resp_dict[server_guid]

        # blob SPNEGO = ByteCount - 16 octets restants, à partir du byte 85
        local -i blob_len=$(( bc - 16 ))
        if (( blob_len > 0 )); then
            hex::slice "${msg}" 85 "${blob_len}" _smb1_neg_resp_dict[spnego_blob]
        else
            _smb1_neg_resp_dict[spnego_blob]=""
        fi
    else
        _smb1_neg_resp_dict[ext_sec]="0"

        # Mode challenge direct : ChallengeLength octets à partir de byte 69
        if (( chal_len == 8 )); then
            hex::slice "${msg}" 69 8 _smb1_neg_resp_dict[challenge]
        fi
        # DomainName suit le challenge (unicode)
        _smb1_neg_resp_dict[server_guid]=""
        _smb1_neg_resp_dict[spnego_blob]=""
    fi

    log::debug "smb1::negotiate : status=0x$(printf '%08X' ${_smb1_neg_resp_dict[status]}) ext_sec=${_smb1_neg_resp_dict[ext_sec]} caps=0x$(printf '%08X' ${caps})"
}
