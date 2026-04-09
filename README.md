# Ensh

> Implémentation de protocoles réseau Windows en Bash pur.

Ensh est une bibliothèque modulaire qui apporte à Bash les capacités qu'[impacket](https://github.com/fortra/impacket) offre à Python : interagir avec les protocoles du monde Windows (SMB, NTLM, Kerberos, LDAP, NetBIOS…) sans quitter le shell.

Zéro dépendance compilée. Zéro binaire externe obligatoire. Du Bash, point.

---

## Pourquoi Ensh ?

| | impacket (Python) | Manticore (Go) | **Ensh (Bash)** |
|---|---|---|---|
| Langage | Python 3 | Go | Bash ≥ 5.0 |
| Dépendances | pip | go modules | aucune |
| Intégration shell | via subprocess | via subprocess | **native** |
| Portabilité | partout avec Python | compilation requise | partout avec bash |

Ensh n'est pas un portage d'impacket ni de Manticore. C'est une nouvelle approche, pensée pour le shell.

---

## Structure du projet

```
ensh.sh              — Chargeur principal (point d'entrée)
lib/
  core/              — Fondations : import, log, bytes, hex, endianness
  crypto/            — Primitives : MD4, HMAC-MD5, RC4, NT/LM hash
  encoding/          — UTF-16LE, Base64, ASN.1 DER
  protocol/          — Implémentations des protocoles
    netbios/         — NetBIOS over TCP (NBT)
    ntlm/            — Authentification NTLM (v1/v2)
    smb/smb1/        — SMB 1.0
    smb/smb2/        — SMB 2.x / 3.x
    kerberos/        — Kerberos 5
    ldap/            — LDAP / LDAPS
  transport/         — Couche TCP et UDP (/dev/tcp, /dev/udp)
tools/               — Outils standalone (smbclient, secretsdump…)
tests/               — Suite de tests unitaires
examples/            — Exemples d'utilisation
docs/                — Références de protocoles et spécifications
```

---

## Utilisation rapide

```bash
# Charger la bibliothèque complète
source ensh.sh

# Ou importer uniquement ce dont on a besoin
ensh::import protocol/ntlm

# Créer un message Negotiate NTLM
ntlm::negotiate::build my_msg
ntlm::negotiate::set_flags my_msg "$(ntlm::flags::default)"
ntlm::negotiate::encode my_msg hex_output
```

---

## Conventions de code

- Toutes les fonctions sont namespaced : `module::sous_module::fonction`
- Les données binaires circulent en hexadécimal (`DEADBEEF`, sans `0x`)
- L'endianness est explicite : `core::endian::le16`, `core::endian::be32`
- Chaque module déclare ses dépendances en tête de fichier via `ensh::import`
- Les tests sont co-localisés dans `tests/` et suivent la même hiérarchie

---

## Prérequis

- Bash ≥ 5.0
- `printf`, `xxd`, `od` (présents dans toute distribution Linux/macOS)
- `openssl` (optionnel, accélère certaines opérations crypto)

---

## Licence

MIT — voir [LICENSE](LICENSE)
