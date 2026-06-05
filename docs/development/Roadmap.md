# Roadmap

## Where we are now

- **Overall**: Ensh is mostly complete on the network stack. Core, Encoding, Transport, Crypto, and the main protocol layers are functional. The Server layer is now implemented. Remaining: Kerberos ccache/PAC and SMB 3.x encryption.

### Core (complete)
- **Implemented**: bytes, endian, hex, log.

### Encoding (complete)
- **Implemented**: asn1, base64, utf16.

### Transport (complete)
- **Implemented**: tcp, tls, udp.

### Crypto (complete)
- **Implemented**: md4, rc4, nt_hash, lm_hash, hmac_md5, hmac_sha256, aes_cmac, ntlmv1.

### Network (mostly complete)
- **NTLM**: Complete - negotiate, challenge, authenticate (NTLMv2, flags, signing).
- **SMB 1.0**: Partly complete - negotiate, session setup (NTLMSSP), tree connect.
- **SMB 2.x**: Complete - negotiate, session setup, tree connect, signing (HMAC-SHA256), IOCTL, create, read, write, close, query_directory.
- **SMB 3.x**: Signing only (AES-CMAC). Encryption pending.
- **DCE/RPC**: Complete - bind, request over SMB2 IOCTL.
- **MSRPC/SRVSVC**: Complete - NetrShareEnum (share enumeration).
- **MSRPC/LSARPC**: Complete - SID lookup, RID brute force.
- **MSRPC/SAMR**: Complete - connect, lookup_domain, open_domain, enumerate_users (validated on Windows DC).
- **LDAP**: Complete - session, bind, search, filter, add, modify.
- **Kerberos**: Partly complete - AS-REQ (AS-REP roasting), TGS-REQ. No ccache or PAC parsing yet.
- **LLMNR**: Complete - wire format (RFC 4795), client (multicast query), server (poisoning via socat).
- **NetBIOS/NBT**: Complete - NBT session transport + NBNS (UDP/137 queries and poisoning).
- **DNS**: Complete - pure bash DNS query (RFC 1035). A, AAAA, PTR, MX, NS, TXT, SRV. TCP fallback for truncated responses.

### Server (complete)
- **SMB capture server**: Complete - SMB2 negotiate + SessionSetup (NTLM type 1/2/3) capture, hashcat NTLMv2 output.
- **HTTP capture server**: Complete - 401 WWW-Authenticate NTLM flow, WPAD/PAC response.

---

## Remaining steps (recommended order)

1. ~~Fix `samr::open_domain` on all targets (MSRPC/SAMR stabilization).~~ Done.
2. ~~Implement NBNS - NBT-NS poisoning companion to LLMNR.~~ Done.
3. ~~Implement SMB capture server (SMB2 minimal auth listener).~~ Done.
4. ~~Implement HTTP capture server (NTLM 401 relay).~~ Done.
5. ~~Implement DNS query (pure bash, RFC 1035).~~ Done.
6. Stabilize Kerberos - ccache read/write, PAC parsing.
7. SMB 3.x full dialect support (encryption, pre-auth integrity).

---

## Status legend

- **Green**: Implemented and tested
- **Orange**: Partly complete or known issues
- **Red**: To do
