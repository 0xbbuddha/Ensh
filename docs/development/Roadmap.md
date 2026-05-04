# Roadmap

## Where we are now

- **Overall**: Ensh is partly complete. Core, Encoding, Transport, and most of the Network stack are functional. The Server layer (SMB capture, HTTP capture) is planned but not yet started.

### Core (complete)
- **Implemented**: bytes, endian, hex, log.

### Encoding (complete)
- **Implemented**: asn1, base64, utf16.

### Transport (complete)
- **Implemented**: tcp, tls, udp.

### Crypto (complete)
- **Implemented**: md4, rc4, nt_hash, lm_hash, hmac_md5, hmac_sha256, aes_cmac, ntlmv1.

### Network (partly complete)
- **NTLM**: Complete — negotiate, challenge, authenticate (NTLMv2, flags, signing).
- **SMB 1.0**: Partly complete — negotiate, session setup (NTLMSSP), tree connect.
- **SMB 2.x**: Complete — negotiate, session setup, tree connect, signing (HMAC-SHA256), IOCTL, create, read, write, close, query_directory.
- **SMB 3.x**: Signing only (AES-CMAC). Full dialect support pending.
- **DCE/RPC**: Complete — bind, request over SMB2 IOCTL.
- **MSRPC/SRVSVC**: Complete — NetrShareEnum (share enumeration).
- **MSRPC/LSARPC**: Complete — SID lookup, RID brute force.
- **MSRPC/SAMR**: Partly complete — connect, lookup_domain, open_domain, enumerate_users. open_domain has a known issue on some targets.
- **LDAP**: Complete — session, bind, search, filter, add, modify.
- **Kerberos**: Partly complete — AS-REQ (AS-REP roasting), TGS-REQ. No ccache or PAC parsing yet.
- **LLMNR**: Complete — wire format (RFC 4795), client (multicast query), server (poisoning via socat).
- **NetBIOS/NBT**: Partly complete — NBT session transport present. NBNS (UDP/137 queries and poisoning) pending.
- **DNS**: To do — pure bash DNS query (RFC 1035).

### Server (to do)
- **SMB capture server**: SMB2 negotiate + SessionSetup (NTLM type 1/2/3) capture, hashcat NTLMv2 output.
- **HTTP capture server**: 401 WWW-Authenticate NTLM flow, optional WPAD response.

---

## Remaining steps (recommended order)

1. Fix `samr::open_domain` on all targets (MSRPC/SAMR stabilization).
2. Implement NBNS — NBT-NS poisoning companion to LLMNR.
3. Implement SMB capture server (SMB2 minimal auth listener).
4. Implement HTTP capture server (NTLM 401 relay).
5. Implement DNS query (pure bash, RFC 1035).
6. Stabilize Kerberos — ccache read/write, PAC parsing.
7. SMB 3.x full dialect support (encryption, pre-auth integrity).

---

## Status legend

- **Green**: Implemented and tested
- **Orange**: Partly complete or known issues
- **Red**: To do
