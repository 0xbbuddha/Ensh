#!/usr/bin/env bash
#
# lib/protocol/smb/smb1/session_setup.sh — SMB_COM_SESSION_SETUP_ANDX (0x73)
#
# Implémente l'authentification SMB1 en mode Extended Security (SPNEGO/NTLMSSP).
# L'échange se déroule en deux allers-retours :
#
#   1. Client → SMB SessionSetup #1 avec SPNEGO NegTokenInit (NTLM Negotiate)
#      Serveur → STATUS_MORE_PROCESSING_REQUIRED + SPNEGO NegTokenResp (NTLM Challenge)
#
#   2. Client → SMB SessionSetup #2 avec SPNEGO NegTokenResp (NTLM Authenticate)
#      Serveur → STATUS_SUCCESS (+ éventuellement NegTokenResp final)
#
# Requête (WordCount=12) :
#   [SMB header]
#   WC=12
#   AndXCommand     : 0xFF (pas de chaining)
#   AndXReserved    : 0x00
#   AndXOffset      : 0x0000
#   MaxBufferSize   : LE16 — taille max de buffer SMB acceptée
#   MaxMpxCount     : LE16
#   VcNumber        : LE16 — numéro de circuit virtuel (1 pour la première session)
#   SessionKey      : LE32 — clé de session du Negotiate
#   SecurityBlobLen : LE16 — longueur du blob SPNEGO
#   Reserved2       : LE32 = 0
#   Capabilities    : LE32 — capacités du client
#   ByteCount       : LE16 = SecurityBlobLen + taille des strings optionnelles
#   SecurityBlob    : blob SPNEGO
#   NativeOS        : chaîne OEM ou Unicode (optionnelle, terminée par 00[00])
#   NativeLanMan    : idem
#
# Réponse (WordCount=4) :
#   [SMB header] (status = MORE_PROCESSING ou SUCCESS, uid assigné)
#   WC=4
#   AndXCommand, AndXReserved, AndXOffset
#   Action          : LE16 — 0=user, 1=guest
#   SecurityBlobLen : LE16
#   ByteCount       : LE16
#   SecurityBlob    : blob SPNEGO de réponse
#
# Dépendances : core/endian, core/log, protocol/smb/smb1/header
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_ENSH_SMB1_SESSION_SETUP:-}" ]] && return 0
readonly _ENSH_SMB1_SESSION_SETUP=1

ensh::import core/endian
ensh::import core/log
ensh::import protocol/smb/smb1/header

# ── Capacités client par défaut ───────────────────────────────────────────────
#
# CAP_UNICODE | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_EXTENDED_SECURITY
readonly SMB1_CLIENT_CAPS=$(( SMB1_CAP_UNICODE | SMB1_CAP_NT_SMBS | SMB1_CAP_STATUS32 \
                             | SMB1_CAP_LEVEL_II_OPLOCKS | SMB1_CAP_EXTENDED_SECURITY ))

# ── Helpers de construction ───────────────────────────────────────────────────

# _smb1_ss_build_body <spnego_blob_hex> <session_key_int> <var_body_out>
#
# Construit le corps (words + data) d'un SMB_COM_SESSION_SETUP_ANDX.
# Commun aux deux phases d'authentification (seul le blob change).
_smb1_ss_build_body() {
    local spnego="${1^^}"
    local -i session_key="$2"
    local -n _smb1_ss_bb_out="$3"

    local -i blob_len=$(( ${#spnego} / 2 ))

    # Chaînes optionnelles : deux null bytes pour chacune (OEM mode)
    local native_os="00"
    local native_lm="00"
    local extra="${native_os}${native_lm}"
    local -i extra_len=$(( ${#extra} / 2 ))
    local -i bc=$(( blob_len + extra_len ))

    local blob_len_le sess_key_le caps_le bc_le
    endian::le16 "${blob_len}"     blob_len_le
    endian::le32 "${session_key}"  sess_key_le
    endian::le32 "${SMB1_CLIENT_CAPS}" caps_le
    endian::le16 "${bc}"           bc_le

    local max_buf_le; endian::le16 65535 max_buf_le  # MaxBufferSize client
    local max_mpx_le; endian::le16 2     max_mpx_le  # MaxMpxCount
    local vc_le;      endian::le16 1     vc_le        # VcNumber

    # Words (12 mots = 24 octets)
    local words=""
    words+="FF"              # AndXCommand = 0xFF (no chain)
    words+="00"              # AndXReserved
    words+="0000"            # AndXOffset
    words+="${max_buf_le}"   # MaxBufferSize
    words+="${max_mpx_le}"   # MaxMpxCount
    words+="${vc_le}"        # VcNumber
    words+="${sess_key_le}"  # SessionKey
    words+="${blob_len_le}"  # SecurityBlobLength
    words+="00000000"        # Reserved2
    words+="${caps_le}"      # Capabilities

    _smb1_ss_bb_out="${words}${bc_le}${spnego}${extra}"
}

# ── Construction des requêtes ─────────────────────────────────────────────────

# smb1::session_setup::build_ntlm_init <var_out> <spnego_neg_blob_hex>
#                                      [pid] [session_key_int]
#
# Construit le PREMIER SMB_COM_SESSION_SETUP_ANDX (NTLM Negotiate encapsulé).
# uid=0 car l'utilisateur n'est pas encore authentifié.
smb1::session_setup::build_ntlm_init() {
    local -n _smb1_ssi_out="$1"
    local spnego="${2^^}"
    local -i pid="${3:-1234}"
    local -i session_key="${4:-0}"

    local hdr
    smb1::header::build hdr \
        "${SMB1_CMD_SESSION_SETUP_ANDX}" \
        0 "${pid}" 0 2 \
        "${SMB1_DEFAULT_FLAGS}" "${SMB1_DEFAULT_FLAGS2}"

    local body
    _smb1_ss_build_body "${spnego}" "${session_key}" body

    local wc="0C"   # WordCount = 12
    local smb="${hdr}${wc}${body}"

    smb1::nbt_wrap "${smb}" _smb1_ssi_out
    log::debug "smb1::session_setup : NTLM Negotiate prêt"
}

# smb1::session_setup::build_ntlm_auth <var_out> <spnego_auth_blob_hex>
#                                      <uid_int> [pid] [session_key_int]
#
# Construit le TROISIÈME SMB_COM_SESSION_SETUP_ANDX (NTLM Authenticate).
# uid = valeur reçue dans la réponse au premier SessionSetup.
smb1::session_setup::build_ntlm_auth() {
    local -n _smb1_ssa_out="$1"
    local spnego="${2^^}"
    local -i uid="$3"
    local -i pid="${4:-1234}"
    local -i session_key="${5:-0}"

    local hdr
    smb1::header::build hdr \
        "${SMB1_CMD_SESSION_SETUP_ANDX}" \
        0 "${pid}" "${uid}" 3 \
        "${SMB1_DEFAULT_FLAGS}" "${SMB1_DEFAULT_FLAGS2}"

    local body
    _smb1_ss_build_body "${spnego}" "${session_key}" body

    local wc="0C"
    local smb="${hdr}${wc}${body}"

    smb1::nbt_wrap "${smb}" _smb1_ssa_out
    log::debug "smb1::session_setup : NTLM Authenticate prêt (uid=${uid})"
}

# ── Parsing de la réponse ─────────────────────────────────────────────────────

# smb1::session_setup::parse_response <hex_msg> <var_dict_out>
#
# Parse une réponse SMB_COM_SESSION_SETUP_ANDX.
# Remplit le tableau associatif avec :
#   status      — NT Status (décimal)
#   uid         — User ID assigné par le serveur
#   action      — 0=user, 1=guest
#   spnego_blob — blob SPNEGO de réponse (hex, peut être vide)
# Retourne 0 même si status=MORE_PROCESSING (l'appelant doit vérifier status).
smb1::session_setup::parse_response() {
    local msg="${1^^}"
    local -n _smb1_ss_pr_dict="$2"

    # ── En-tête ────────────────────────────────────────────────────────────
    local -A _hdr
    smb1::header::parse "${msg}" _hdr || return 1

    _smb1_ss_pr_dict[status]="${_hdr[status]}"
    _smb1_ss_pr_dict[uid]="${_hdr[uid]}"

    # ── WordCount ──────────────────────────────────────────────────────────
    local -i wc=$(( 16#${msg:64:2} ))

    if (( wc == 0 )); then
        # Réponse d'erreur courte (ex: logon failure)
        _smb1_ss_pr_dict[action]=0
        _smb1_ss_pr_dict[spnego_blob]=""
        return 0
    fi

    # ── Action (word à l'offset byte 37, nibble 74) ────────────────────────
    endian::read_le16 "${msg}" 37 _smb1_ss_pr_dict[action]

    # ── SecurityBlobLength (byte 39) ───────────────────────────────────────
    local -i blob_len
    endian::read_le16 "${msg}" 39 blob_len

    # ── ByteCount (byte 41-42) ─────────────────────────────────────────────
    # byte 33 + 4*2 = 33+8=41 (wc=4, 4 words = 8 bytes → bytes 33-40, bc at 41)
    local -i bc
    endian::read_le16 "${msg}" 41 bc

    # ── SecurityBlob (byte 43+) ────────────────────────────────────────────
    if (( blob_len > 0 )); then
        hex::slice "${msg}" 43 "${blob_len}" _smb1_ss_pr_dict[spnego_blob]
    else
        _smb1_ss_pr_dict[spnego_blob]=""
    fi

    log::debug "smb1::session_setup : status=0x$(printf '%08X' ${_smb1_ss_pr_dict[status]}) uid=${_smb1_ss_pr_dict[uid]} action=${_smb1_ss_pr_dict[action]} blob_len=${blob_len}"
}
