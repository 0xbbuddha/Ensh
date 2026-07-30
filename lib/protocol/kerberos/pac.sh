#!/usr/bin/env bash
#
# lib/protocol/kerberos/pac.sh - Privilege Attribute Certificate (MS-PAC)
#
# Parse la structure PAC presente dans les tickets Kerberos Windows.
# Le PAC contient l'identite de l'utilisateur (nom, domaine, RID, groupes).
#
# Implemente :
#   - pac::parse           : parse PACTYPE + extrait CLIENT_INFO et UPN_DNS_INFO
#   - pac::parse_logon_info: extrait les champs fixes du KERB_VALIDATION_INFO
#
# Note : KERB_VALIDATION_INFO (LOGON_INFO) est encode en NDR32 complet.
# pac::parse_logon_info extrait les champs au debut du stream (username, domain)
# sans decoder entierement le NDR32 - suffisant pour les cas offensifs courants.
#
# Dependances : core/endian, core/log, core/hex, encoding/utf16
#
# Reference : MS-PAC section 2
#
# ─────────────────────────────────────────────────────────────────────────────

[[ -n "${_BK_KRB_PAC:-}" ]] && return 0
readonly _BK_KRB_PAC=1

bk::import core/endian
bk::import core/log
bk::import core/hex
bk::import encoding/utf16

# ── Constantes PAC ───────────────────────────────────────────────────────────

readonly PAC_TYPE_LOGON_INFO=1         # KERB_VALIDATION_INFO (NDR32 complexe)
readonly PAC_TYPE_CREDENTIALS=2
readonly PAC_TYPE_SERVER_CHECKSUM=6
readonly PAC_TYPE_PRIVSVR_CHECKSUM=7
readonly PAC_TYPE_CLIENT_INFO=10       # PAC_CLIENT_INFO (simple)
readonly PAC_TYPE_DELEGATION=12
readonly PAC_TYPE_UPN_DNS_INFO=16      # PAC_UPN_DNS_INFO (simple)

# ── Helpers internes ─────────────────────────────────────────────────────────

# _pac_read_le16 <hex_msg> <offset_bytes> <var_out>
_pac_read_le16() { endian::read_le16 "$1" "$2" "$3"; }

# _pac_read_le32 <hex_msg> <offset_bytes> <var_out>
_pac_read_le32() { endian::read_le32 "$1" "$2" "$3"; }

# _pac_filetime_to_unix <8B_LE_hex> <var_out>
# Convertit un FILETIME Windows (100-ns depuis 01/01/1601) en timestamp Unix.
_pac_filetime_to_unix() {
    local ft_hex="${1^^}"; local -n _pftu_out="$2"
    local -i lo=$(( 16#${ft_hex:0:8} ))
    local -i hi=$(( 16#${ft_hex:8:8} ))
    local -i ft=$(( (hi << 32) | lo ))
    _pftu_out=$(( (ft - 116444736000000000) / 10000000 ))
}

# ── API publique ─────────────────────────────────────────────────────────────

# pac::parse <pac_hex> <var_dict_out>
#
# Parse une structure PACTYPE et extrait les buffers disponibles.
# Remplit le dict avec :
#   buffer_count     - nombre de buffers PAC
#   username         - depuis CLIENT_INFO (champ Name)
#   logon_time       - timestamp Unix depuis CLIENT_INFO
#   upn              - UPN depuis PAC_UPN_DNS_INFO (ex: user@domain.com)
#   dns_domain       - domaine DNS depuis PAC_UPN_DNS_INFO
#   logon_info_hex   - buffer LOGON_INFO brut pour pac::parse_logon_info
#   server_checksum  - hex du buffer SERVER_CHECKSUM
pac::parse() {
    local pac="${1^^}"
    local -n _pp_dict="$2"

    (( ${#pac} >= 16 )) || { log::error "pac::parse : PAC trop court"; return 1; }

    # -- PACTYPE header (8B) --------------------------------------------------
    # cBuffers: uint32 LE
    # Version:  uint32 LE (must be 0)
    local -i cbuffers; _pac_read_le32 "${pac}" 0 cbuffers
    local -i version;  _pac_read_le32 "${pac}" 4 version

    _pp_dict[buffer_count]="${cbuffers}"

    if (( version != 0 )); then
        log::error "pac::parse : version PAC inattendue: ${version}"
        return 1
    fi

    # -- PAC_INFO_BUFFER array (16B chacun) -----------------------------------
    # Chaque entree: ulType(4) + cbBufferSize(4) + Offset(8)
    local -i i entry_off=8
    for (( i=0; i<cbuffers; i++ )); do
        (( entry_off + 16 > ${#pac} / 2 )) && break

        local -i btype bsize
        _pac_read_le32 "${pac}" "${entry_off}"       btype
        _pac_read_le32 "${pac}" "$(( entry_off + 4 ))" bsize

        # Offset est sur 8 octets mais on ne lit que les 4 bas (suffisant pour < 4GB)
        local -i boffset; _pac_read_le32 "${pac}" "$(( entry_off + 8 ))" boffset

        local buf_hex="${pac:$(( boffset * 2 )):$(( bsize * 2 ))}"

        case "${btype}" in
            ${PAC_TYPE_CLIENT_INFO})
                # ClientId (8B FILETIME LE) + NameLength (2B LE) + Name (UTF-16LE)
                (( ${#buf_hex} >= 20 )) || continue
                local ft_hex="${buf_hex:0:16}"  # FILETIME (8B LE)
                local -i name_len; _pac_read_le16 "${buf_hex}" 8 name_len
                local name_hex="${buf_hex:20:$(( name_len * 2 ))}"
                local username
                utf16::decode_le "${name_hex}" username
                _pp_dict[username]="${username}"
                local logon_ts; _pac_filetime_to_unix "${ft_hex}" logon_ts
                _pp_dict[logon_time]="${logon_ts}"
                log::debug "pac : CLIENT_INFO -> username=${username}"
                ;;

            ${PAC_TYPE_UPN_DNS_INFO})
                # UpnLength(2) + UpnOffset(2) + DnsDomainNameLength(2) + DnsDomainNameOffset(2) + Flags(4)
                (( ${#buf_hex} >= 16 )) || continue
                local -i upn_len upn_off dns_len dns_off
                _pac_read_le16 "${buf_hex}" 0 upn_len
                _pac_read_le16 "${buf_hex}" 2 upn_off
                _pac_read_le16 "${buf_hex}" 4 dns_len
                _pac_read_le16 "${buf_hex}" 6 dns_off

                local upn dns_domain
                local upn_hex="${buf_hex:$(( upn_off * 2 )):$(( upn_len * 2 ))}"
                local dns_hex="${buf_hex:$(( dns_off * 2 )):$(( dns_len * 2 ))}"
                utf16::decode_le "${upn_hex}" upn
                utf16::decode_le "${dns_hex}" dns_domain
                _pp_dict[upn]="${upn}"
                _pp_dict[dns_domain]="${dns_domain}"
                log::debug "pac : UPN_DNS_INFO -> upn=${upn} domain=${dns_domain}"
                ;;

            ${PAC_TYPE_LOGON_INFO})
                _pp_dict[logon_info_hex]="${buf_hex}"
                ;;

            ${PAC_TYPE_SERVER_CHECKSUM})
                _pp_dict[server_checksum]="${buf_hex}"
                ;;
        esac

        (( entry_off += 16 ))
    done

    return 0
}

# pac::parse_logon_info <logon_info_hex> <var_dict_out>
#
# Extrait les champs principaux du KERB_VALIDATION_INFO (NDR32).
# Remplit le dict avec :
#   username   - nom d'utilisateur (RPC_UNICODE_STRING)
#   full_name  - nom complet
#   domain     - nom court du domaine
#   user_rid   - RID de l'utilisateur
#   group_rid  - RID du groupe principal
#   logon_time - timestamp FILETIME
#
# Note : Le KERB_VALIDATION_INFO est encode en NDR32 full.
# La structure fixe commence a l'offset 8 (apres le NDR header referent de 4B
# et le pointeur unique de 4B). Les FILETIME sont LE64, les RIDs sont LE32.
# Les RPC_UNICODE_STRING (Length/MaxLength/Pointer) sont aux offsets connus.
#
# Layout du debut de KERB_VALIDATION_INFO (offset depuis debut des donnees NDR) :
#   +0   LogonTime (8B FILETIME)
#   +8   LogoffTime (8B)
#   +16  KickOffTime (8B)
#   +24  PasswordLastSet (8B)
#   +32  PasswordCanChange (8B)
#   +40  PasswordMustChange (8B)
#   +48  EffectiveName (8B RPC_UNICODE_STRING: Len+MaxLen+Ptr)
#   +56  FullName (8B)
#   +64  LogonScript (8B)
#   +72  ProfilePath (8B)
#   +80  HomeDirectory (8B)
#   +88  HomeDirectoryDrive (8B)
#   +96  LogonCount (2B)
#   +98  BadPasswordCount (2B)
#   +100 UserId (4B) <- UserRID
#   +104 PrimaryGroupId (4B) <- GroupRID
#   +108 GroupCount (4B)
#   +112 GroupIds (4B pointer)
#   +116 UserFlags (4B)
#   +120 UserSessionKey (16B)
#   +136 LogonServer (8B RPC_UNICODE_STRING)
#   +144 LogonDomainName (8B RPC_UNICODE_STRING)
#   ... pointeur referent pour LogonDomainId ...
pac::parse_logon_info() {
    local buf="${1^^}"
    local -n _ppli_dict="$2"

    # Le buffer commence par le NDR RPC header (4B referent) + unique pointer (4B)
    # Puis le corps NDR de KERB_VALIDATION_INFO
    # Les deferred referents des strings suivent apres la structure fixe

    # Taille minimale : 4B referent + 4B ptr + 116B minimum
    (( ${#buf} >= 248 )) || return 1

    # Le NDR stream : 4B referent + 4B unique ptr server = 8B de preambule NDR
    # Le corps fixe commence a l'offset 8
    local -i base=8

    # LogonTime (offset 0 depuis base)
    local ft_lo ft_hi ft_hex
    local -i ft_lo_v ft_hi_v
    _pac_read_le32 "${buf}" "${base}" ft_lo_v
    _pac_read_le32 "${buf}" "$(( base + 4 ))" ft_hi_v
    printf -v ft_hex '%08X%08X' "${ft_lo_v}" "${ft_hi_v}"
    # FILETIME en LE -> inverser pour _pac_filetime_to_unix
    local ft_le="${buf:$(( base * 2 )):16}"
    local logon_ts; _pac_filetime_to_unix "${ft_le}" logon_ts
    _ppli_dict[logon_time]="${logon_ts}"

    # UserId / UserRID a l'offset base+100
    local -i user_rid
    _pac_read_le32 "${buf}" "$(( base + 100 ))" user_rid
    _ppli_dict[user_rid]="${user_rid}"

    # PrimaryGroupId a l'offset base+104
    local -i group_rid
    _pac_read_le32 "${buf}" "$(( base + 104 ))" group_rid
    _ppli_dict[group_rid]="${group_rid}"

    # Les RPC_UNICODE_STRING sont : Len(2B LE) + MaxLen(2B LE) + Ptr(4B LE)
    # EffectiveName a l'offset base+48 : Len a base+48
    local -i eff_len; _pac_read_le16 "${buf}" "$(( base + 48 ))" eff_len
    # FullName a l'offset base+56
    local -i full_len; _pac_read_le16 "${buf}" "$(( base + 56 ))" full_len
    # LogonServer a base+136
    local -i srv_len; _pac_read_le16 "${buf}" "$(( base + 136 ))" srv_len
    # LogonDomainName a base+144
    local -i dom_len; _pac_read_le16 "${buf}" "$(( base + 144 ))" dom_len

    # Les deferred referents des strings commencent apres la structure fixe.
    # Taille structure fixe : base + 152 + GroupIds_ptr(4) + ... (environ 200B)
    # On cherche les strings deferred a partir de base+200 (approximation)
    # Chaque string defere : MaxCount(4B) + Offset(4B) + ActualCount(4B) + chars
    local -i deferred_off=$(( base + 200 ))

    # Aligner a 4 octets
    (( deferred_off % 4 != 0 )) && (( deferred_off += 4 - deferred_off % 4 ))

    # Lire les strings dans l'ordre de la structure (referents en ordre de declaration)
    # EffectiveName
    if (( eff_len > 0 && deferred_off + 12 + eff_len <= ${#buf} / 2 )); then
        (( deferred_off += 12 ))  # MaxCount + Offset + ActualCount
        local eff_hex="${buf:$(( deferred_off * 2 )):$(( eff_len * 2 ))}"
        local username; utf16::decode_le "${eff_hex}" username
        _ppli_dict[username]="${username}"
        (( deferred_off += eff_len ))
        # Aligner a 4 octets
        (( eff_len % 2 != 0 )) && (( deferred_off++ ))
    fi

    # FullName
    if (( full_len > 0 && deferred_off + 12 + full_len <= ${#buf} / 2 )); then
        (( deferred_off += 12 ))
        local full_hex="${buf:$(( deferred_off * 2 )):$(( full_len * 2 ))}"
        local full_name; utf16::decode_le "${full_hex}" full_name
        _ppli_dict[full_name]="${full_name}"
        (( deferred_off += full_len ))
    fi

    # Sauter LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive
    local -i skip_idx
    local -i base_sk=$(( base + 64 ))
    for (( skip_idx=0; skip_idx<4; skip_idx++ )); do
        local -i sk_len; _pac_read_le16 "${buf}" "$(( base_sk + skip_idx * 8 ))" sk_len
        if (( sk_len > 0 && deferred_off + 12 + sk_len <= ${#buf} / 2 )); then
            (( deferred_off += 12 + sk_len ))
        fi
    done

    # LogonDomainName (si disponible)
    if (( dom_len > 0 && deferred_off + 12 + dom_len <= ${#buf} / 2 )); then
        (( deferred_off += 12 ))
        local dom_hex="${buf:$(( deferred_off * 2 )):$(( dom_len * 2 ))}"
        local domain; utf16::decode_le "${dom_hex}" domain
        _ppli_dict[domain]="${domain}"
    fi

    return 0
}
