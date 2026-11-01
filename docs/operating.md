# whoHit

Monitoring on `20.119.52.2` (Azure VM "PointingBox", Ubuntu 24.04) to see what
still reaches for this IP, and which old domain names clients ask for, before
deciding the old domains/services are safe to let go.

## Viewing the dashboard

The dashboard listens only on the box's `127.0.0.1:8088`. Tunnel to it:

```sh
ssh -N whohit-dash          # alias in ~/.ssh/config, same as:
ssh -N -L 8088:127.0.0.1:8088 -i ~/.ssh/whohit_ed25519 <user>@20.119.52.2
```

then open <http://localhost:8088>. It refreshes every 20 seconds.

## SSH access

Password login is disabled (`/etc/ssh/sshd_config.d/00-key-only.conf`, which
wins over cloud-init's `50-cloud-init.conf`). Root login is off. The only way
in is `~/.ssh/whohit_ed25519` (`ssh whohit`). If the key is lost, recover through
the Azure portal: Serial console, or "Reset password" / Run command.

## What is recorded

| Table | Written by | One row per |
|---|---|---|
| `attempts` | `sniffer.py` | inbound TCP SYN, UDP flow (per source+port+minute), or ping, with source IP, destination port, protocol. UDP DNS queries also get the query name. |
| `sessions` | `listener.py` | TCP connection the catch-all listener handled: what the client spoke, plus HTTP Host/path/User-Agent, TLS SNI/ALPN, SMTP envelope, request-body field names, or the first bytes. |
| `ip_info` | `enrich.py` | source IP: AS number and network name, country (Team Cymru bulk whois), reverse DNS, and a kind: `scanner`, `hosting` (cloud) or `isp` (everything else). |

nftables (`/etc/whohit/redirect.nft`) redirects **every inbound TCP port except
22** to the listener on `:9999`, so any service that used to live on any port
gets an answer and is logged under its original port. The rule is added when
`whohit-listener` starts and removed when it stops.

## Telling people from scanners

`enrich.py` labels every source address within about a minute of first contact.
An address counts as a **scanner** when it says so (User-Agent such as Censys,
zgrab, Palo Alto, Infrawatch; reverse DNS such as `*.shadowserver.org`; networks
such as Censys, BitSight, Meta's link fetchers), or when it behaves like one:
touches 5+ ports, fetches `robots.txt`, probes for an open proxy, or probes DNS
server details. Generic HTTP libraries (curl, python-requests, Go) are
deliberately *not* treated as scanners, because an old script or app still
calling a domain is exactly what this is looking for. Otherwise, known
cloud/hosting networks are **hosting** and the rest are **ISP/other**. That last
group is where real people are, but small hosting companies and infected home
devices land there too, so it means "worth a look", not proof.

The rules live at the top of `enrich.py`; every restart re-applies them to all
addresses already labelled.

## Your domains

`/etc/whohit/watch.txt` lists the domains this experiment is about (one per
line, subdomains included). The dashboard shows them in their own table,
grouped by domain, with a count of ISP/other sources, and keeps every other
hostname (vhost-testing crawlers, decoy SNI) in a separate table. Edit the file
on the box; the dashboard picks it up on the next refresh.

## Flags

Signals that something real still depends on a name (the `flags` column, shown
as badges in the dashboard):

- **Login form posted**: a request body had password-like fields (a login form
  being submitted, which is what a victim on a former phishing domain would do).
  Only the field names and body size are stored, never the values.
- **Credentials sent**: an HTTP request carried `Authorization`, `Cookie`,
  API-key headers or token-like query parameters. Values are redacted; only
  their presence and length are stored.
- **Cert rejected**: a TLS client refused our self-signed certificate, so it
  validates certificates (browser, mobile app, SDK). Clients that accept the
  certificate get their HTTP request logged like plain HTTP.
- **Mail delivery**: a mail server tried to deliver mail for the domain. The
  listener records the envelope (from/to) and refuses each recipient with a
  temporary `450`, so senders retry and nothing is accepted or bounced
  permanently.
- **Mail login**: a mail client tried SMTP AUTH (only the mechanism is kept).

Login commands in text protocols (IMAP `LOGIN`, POP3/FTP `PASS`, `AUTH`) are
redacted in the stored previews.

Not covered: UDP services beyond the raw hit (QUIC/HTTP3 is visible as "QUIC long
header" on udp/443, but its SNI is not decoded), and IPv6 (the VM has no public
IPv6).

## Layout on the box

```
/opt/whohit/                 code (common, sniffer, listener, enrich, dashboard, static/index.html)
/etc/whohit/                 redirect.nft, watch.txt, self-signed tls.crt/tls.key
/var/lib/whohit/whohit.db    SQLite (WAL)
whohit-sniffer.service       CAP_NET_RAW only, runs as user whohit
whohit-listener.service      unprivileged, loads/unloads the nft redirect
whohit-enrich.service        unprivileged, labels source IPs (outbound whois + reverse DNS)
whohit-dashboard.service     loopback only (bind + systemd IPAddressDeny)
```

## Common tasks

```sh
# Deploy changes from this directory
rsync -a --delete --exclude __pycache__ ./whohit ./deploy whohit:whohit-src/
ssh whohit 'sudo bash whohit-src/deploy/install.sh'

# Logs / status
ssh whohit 'sudo journalctl -u "whohit-*" -f'

# Ad-hoc queries
ssh whohit 'sudo sqlite3 -header -column /var/lib/whohit/whohit.db \
  "SELECT domain, app, COUNT(*) FROM sessions GROUP BY 1,2 ORDER BY 3 DESC LIMIT 30"'

# Pull a copy of the database
ssh whohit 'sudo sqlite3 /var/lib/whohit/whohit.db ".backup /tmp/whohit.db"' && scp whohit:/tmp/whohit.db .

# Stop the experiment (removes the port redirect; ports go back to closed)
ssh whohit 'sudo systemctl disable --now whohit-listener whohit-sniffer whohit-enrich whohit-dashboard'
```
