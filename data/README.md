# Data

Everything `20.119.52.2` logged from 2026-10-17 07:24 to 2026-11-01 08:39 UTC, after
sanitising with [`tools/publish.py`](../tools/publish.py). All times are UTC. Files are
gzipped CSV with a header row. Control characters inside fields are written as `\xNN`,
so every row is one line.

## Files

**`attempts.csv.gz`** has one row per inbound TCP SYN, UDP flow (per source, port and
minute) or ping, as seen by the packet sniffer.

| column | |
|---|---|
| `time` | first packet |
| `src` | source address, or its `anon-` pseudonym (see below) |
| `kind` | `scanner`, `hosting` or `isp`, see [sources](#sourcescsvgz) |
| `proto` | `tcp`, `udp` or `icmp` |
| `dst_port` | empty for ICMP |
| `dns_name` | query name, when a UDP packet was a DNS query |
| `info` | short description of a UDP or ICMP payload (escaped first bytes, or a decoded summary) |

**`sessions.csv.gz`** has one row per TCP connection the catch-all listener handled. Port 22
is the real SSH server and is not in here.

| column | |
|---|---|
| `time`, `src`, `kind`, `dst_port` | as above |
| `app` | what the client spoke: `http`, `https` (TLS then HTTP), `tls` (TLS, no request after), `rdp`, `smb`, `ssh`, `smtp`, ... `silent` = connected and said nothing; `busy` = closed unread because that source already had too many connections open, or the listener was full; `unknown` = bytes no parser recognised |
| `host` | HTTP Host header, TLS SNI, or SMTP recipient domain |
| `method`, `path`, `user_agent` | HTTP request line and user agent |
| `flags` | `login-submit` (a body with password-like field names), `credentials` (an auth/cookie/API-key header or token-like query parameter; values were never stored), `cert-rejected` (TLS client refused the self-signed certificate), `mail`, `smtp-auth` |
| `tls_versions` | versions the ClientHello offered |
| `alpn` | ALPN list the ClientHello offered (JSON) |
| `tls_handshake` | how the handshake ended |
| `headers` | HTTP headers (JSON). Credential values were redacted when captured |
| `body` | request body shape: size, content type, field names only (JSON) |
| `preview` | first bytes of non-HTTP connections, escaped. Login commands (`PASS`, `LOGIN`, `AUTH`) were redacted when captured |

**`smtp.csv`** has one row per SMTP conversation: HELO, MAIL FROM, RCPT TO, the AUTH
mechanism if one was tried, and any other commands. The listener refused every
recipient with `450` and never accepted message data, so there are no message bodies.

<a id="sourcescsvgz"></a>**`sources.csv.gz`** has one row per source address.

| column | |
|---|---|
| `src` | address or pseudonym |
| `kind` | `scanner`: says it is one (user agent, reverse DNS, network) or behaves like one (5+ ports, robots.txt, proxy or DNS-server probes). `hosting`: a cloud or hosting network. `isp`: everything else |
| `asn`, `as_name`, `country` | from Team Cymru's whois. Country is where the address is registered |
| `rdns` | reverse DNS (empty for pseudonymised sources) |
| `scanner_reason` | why it was labelled a scanner |

## What was removed

- **Addresses of people.** Sources labelled `scanner` or `hosting` keep their
  address. Everything labelled `isp` (home, mobile and office lines, where the real
  visitors are) is replaced by `anon-` and 10 hex digits. The pseudonym is an HMAC
  with a random key that was thrown away, and it is consistent within this release
  only. The same address is also replaced wherever it appears inside other fields,
  such as an SMTP `HELO [1.2.3.4]`. Their reverse DNS is dropped. Their country and
  network are kept.
- **For pseudonymised sources**, HTTP header values are blanked (names kept, plus
  `host`, `content-type` and `content-length`), and RDP `mstshash=` usernames
  are redacted.
- **Organisation names in hostnames.** Under the six watched domains, any label
  that is not a generic word becomes `redacted-a`, `redacted-b`, ... (the same name
  always gets the same letter, and `-my` suffixes are kept). Random tokens become `<id>`.
- **Email addresses** keep the first character of the local part and the domain:
  `m***@yahoo.com`. Role mailboxes (`abuse@`, `postmaster@`, `noreply@`, ...) and two
  well-known spam test senders are left as they are.

Addresses of malware download servers and other third parties that appear inside
payloads are left as they are, unless the same address was itself a pseudonymised source.
