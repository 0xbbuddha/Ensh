#!/usr/bin/env bash
#
# examples/ntlm_handshake.sh — Exemple : échange NTLM complet offline
#
# Simule un échange NTLM complet (Negotiate → Challenge → Authenticate)
# sans connexion réseau réelle, pour illustrer l'utilisation de la bibliothèque.
#
# Usage : source ensh.sh && bash examples/ntlm_handshake.sh
#
# ─────────────────────────────────────────────────────────────────────────────

ENSH_LOG_LEVEL="DEBUG"
source "$(dirname "${BASH_SOURCE[0]}")/../ensh.sh"

ensh::import protocol/ntlm/negotiate
ensh::import protocol/ntlm/challenge
ensh::import protocol/ntlm/authenticate
ensh::import protocol/ntlm/flags
ensh::import crypto/nt_hash

echo "════════════════════════════════════"
echo " Ensh — Exemple d'échange NTLM"
echo "════════════════════════════════════"
echo

# ── Paramètres de l'exemple ───────────────────────────────────────────────────

USERNAME="Administrator"
PASSWORD="Password"
DOMAIN="CORP"
WORKSTATION="LAPTOP01"

# ── Étape 1 : Negotiate ───────────────────────────────────────────────────────

printf '\n[1/3] Construction du message NTLM Negotiate...\n'

declare negotiate_msg
ntlm::negotiate::build negotiate_msg "${DOMAIN}" "${WORKSTATION}"

log::hexdump "NTLM Negotiate" "${negotiate_msg}"
printf '  → %d octets\n' "$(( ${#negotiate_msg} / 2 ))"

# ── Étape 2 : Challenge (simulé côté serveur) ─────────────────────────────────

printf '\n[2/3] Construction du message NTLM Challenge (serveur simulé)...\n'

# En conditions réelles, ce message vient du serveur.
# Ici on le construit manuellement pour la démonstration.

SERVER_CHALLENGE="0123456789ABCDEF"

declare target_info
ntlm::challenge::build_target_info target_info \
    "${DOMAIN}" "${WORKSTATION}" \
    "corp.example.com" "${WORKSTATION}.corp.example.com"

printf '  Challenge serveur : %s\n' "${SERVER_CHALLENGE}"

# ── Étape 3 : Authenticate ────────────────────────────────────────────────────

printf '\n[3/3] Construction du message NTLM Authenticate...\n'

# Calculer le NT hash
declare nt_hash
nt_hash::from_password "${PASSWORD}" nt_hash
printf '  NT Hash de "%s" : %s\n' "${PASSWORD}" "${nt_hash}"

# Construire le message Authenticate
declare authenticate_msg
ntlm::authenticate::build authenticate_msg \
    "${USERNAME}" "${DOMAIN}" "${WORKSTATION}" \
    "${nt_hash}" \
    "${SERVER_CHALLENGE}" \
    "${target_info}"

log::hexdump "NTLM Authenticate" "${authenticate_msg}"
printf '  → %d octets\n' "$(( ${#authenticate_msg} / 2 ))"

# ── Vérification (parsing retour) ─────────────────────────────────────────────

printf '\n[Vérification] Parsing du message Authenticate...\n'

declare -A parsed
ntlm::authenticate::parse "${authenticate_msg}" parsed

declare domain_decoded username_decoded workstation_decoded
utf16::decode_le "${parsed[domain]}"      domain_decoded
utf16::decode_le "${parsed[username]}"    username_decoded
utf16::decode_le "${parsed[workstation]}" workstation_decoded

printf '  Domaine      : %s\n' "${domain_decoded}"
printf '  Utilisateur  : %s\n' "${username_decoded}"
printf '  Station      : %s\n' "${workstation_decoded}"
printf '  NT-Proof     : %s\n' "${parsed[nt_proof]}"

echo
echo "════════════════════════════════════"
echo " Échange NTLM terminé."
echo "════════════════════════════════════"
