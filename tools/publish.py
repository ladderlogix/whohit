"""Build the public dataset, result tables and charts from a copy of the whoHit database.

    python3 tools/publish.py logs/whohit-YYYY-MM-DD.db

Writes data/ (sanitised event tables), results/tables/ (aggregates) and
results/charts/ (SVG), relative to the repository root. data/README.md
describes what is removed or masked; in short:

  - Addresses labelled scanner or hosting stay as they are. Everything else
    (home, mobile and office connections, where real people are) becomes a
    pseudonym like anon-3f9c1e0a2b, keyed with a random salt that is not kept.
  - Labels under the six watched domains that are not generic words (they
    name organisations or people) become redacted-a, redacted-b, ...; random
    tokens become <id>.
  - Email addresses keep their domain and first letter.
  - A pseudonymised address is replaced wherever it appears, e.g. in an SMTP HELO.
  - For pseudonymised sources, HTTP header values and RDP usernames are dropped.
"""
import collections
import csv
import datetime
import gzip
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
TABLES = os.path.join(ROOT, "results", "tables")
CHARTS = os.path.join(ROOT, "results", "charts")

WATCHED_HOST = re.compile(
    r"(?i)\b((?:[a-z0-9-]+\.)*)(googledrive|sharepoint|onedrive|outlook|msft|drive)\.download\b")
# Subdomain words that are generic (wordlists, service names, scanner constants), safe to publish.
GENERIC = set("""
    www m ww1 ww7 ww12 ww99 hostmaster ru mobile dev dev2 staging frontend edge archive tickets home
    resolver resolver1 doh doh1 ns ns1 dns dns1 agh adguard backend admin api demo app cy console self
    h4 lp google com ar 40 1c j7 chat remote git sync beamng web pages video ui setup record data r24
    projects project portal mock microsoft hub mandanten intern integrations g file documents dms
    dashboard super event exhibitor detail backup animations chaos android misc xt double dragon zeebo
    mega claw faq io kestra plugin microsoft365 googleworkspace mail protection autodiscover login my
    smtp imap pop pop3 mx webmail owa exchange z9x8c7v6b5 debug trigger""".split())
IPV4 = re.compile(r"(?<![\d.])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})(?!\d)")  # also 1-2-3-4 HELO names
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
EMAIL = re.compile(r"([A-Za-z0-9._%+-]+)(@|%40)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
ROLE_MAILBOX = re.compile(
    r"(?i)^(abuse|security|info|admin|noreply|no-reply|contact|research|support|webmaster|postmaster|"
    r"hostmaster|root|test|scan|scanner)$")
PUBLIC_SENDERS = {"spameri@tiscali.it", "dpr@priv8shop.com"}  # well-known spam/relay-test senders
RDP_USER = re.compile(r"(mstshash=)[^\\]*")
CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")  # escaped so every CSV row stays on one line
KEEP_HEADER_VALUES = {"host", "content-type", "content-length"}


def transitions(s):
    return sum(1 for a, b in zip(s, s[1:]) if a.isdigit() != b.isdigit() and a.isalnum() and b.isalnum())


class Sanitiser:
    def __init__(self, kinds):
        self.kinds = kinds
        self.salt = os.urandom(16)
        self.names = {}
        self.anon = {}

    def kind(self, ip):
        return self.kinds.get(ip, "isp")

    def src(self, ip):
        if self.kind(ip) in ("scanner", "hosting"):
            return ip
        if ip not in self.anon:
            self.anon[ip] = "anon-" + hmac.new(self.salt, ip.encode(), hashlib.sha256).hexdigest()[:10]
        return self.anon[ip]

    def label(self, label):
        low = label.lower()
        if all(part in GENERIC for part in low.split("-")):
            return low
        if UUID.match(low) or transitions(low) >= 4:
            return "<id>"
        base, my = (low[:-3], "-my") if low.endswith("-my") else (low, "")
        if base not in self.names:
            n = len(self.names)
            self.names[base] = "redacted-" + (chr(97 + n) if n < 26 else chr(97 + n // 26 - 1) + chr(97 + n % 26))
        return self.names[base] + my

    def host(self, m):
        labels = [x for x in m.group(1).split(".") if x]
        return ".".join([self.label(x) for x in labels] + [m.group(2).lower(), "download"])

    def email(self, m):
        local, at, domain = m.groups()
        if ROLE_MAILBOX.match(local) or f"{local}@{domain}".lower() in PUBLIC_SENDERS:
            return m.group(0)
        return f"{local[0]}***{at}{domain}"

    def address(self, m):
        ip = ".".join(m.groups())
        return self.src(ip) if ip in self.kinds and self.src(ip) != ip else m.group(0)

    def text(self, s):
        if not s:
            return s
        s = CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", s)
        return IPV4.sub(self.address, EMAIL.sub(self.email, WATCHED_HOST.sub(self.host, s)))


def iso(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def day(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")


def write_csv(path, header, rows):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "wt", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        n = 0
        for row in rows:
            w.writerow(row)
            n += 1
    print(f"  {os.path.relpath(path, ROOT)}: {n} rows")


# ---------------------------------------------------------------- data/

def export_sources(db, s):
    def rows():
        for ip, asn, as_name, cc, rdns, kind, reason in db.execute(
                "SELECT ip, asn, as_name, cc, rdns, kind, reason FROM ip_info ORDER BY ip"):
            anon = s.src(ip) != ip
            yield s.src(ip), kind, asn, as_name, cc, None if anon else rdns, s.text(reason)
    write_csv(os.path.join(DATA, "sources.csv.gz"),
              ["src", "kind", "asn", "as_name", "country", "rdns", "scanner_reason"], rows())


def export_attempts(db, s):
    def rows():
        for ts, ip, proto, port, domain, info in db.execute(
                "SELECT ts, src_ip, proto, dst_port, domain, info FROM attempts ORDER BY id"):
            yield iso(ts), s.src(ip), s.kind(ip), proto, port, s.text(domain), s.text(info)
    write_csv(os.path.join(DATA, "attempts.csv.gz"),
              ["time", "src", "kind", "proto", "dst_port", "dns_name", "info"], rows())


def export_sessions(db, s):
    smtp = []

    def rows():
        for (ts, ip, port, app, domain, method, path, ua, flags, detail, preview) in db.execute(
                "SELECT ts, src_ip, dst_port, app, domain, method, path, user_agent, flags, detail, preview "
                "FROM sessions ORDER BY id"):
            d = json.loads(detail) if detail else {}
            anon = s.src(ip) != ip
            headers = d.get("headers")
            if headers:
                headers = {k: (s.text(v) if not anon or k in KEEP_HEADER_VALUES else "")
                           for k, v in headers.items()}
            if anon and preview:
                preview = RDP_USER.sub(r"\1[redacted]", preview)
            if "smtp" in d:
                e = d["smtp"]
                smtp.append((iso(ts), s.src(ip), s.kind(ip), port, s.text(e.get("helo")),
                             s.text(e.get("mail_from")), " ".join(s.text(r) for r in e.get("rcpt", [])),
                             e.get("auth_mechanism"), s.text(" | ".join(e.get("other", [])))))
            yield (iso(ts), s.src(ip), s.kind(ip), port, app, s.text(domain), s.text(method), s.text(path),
                   s.text(ua), flags, " ".join(d.get("versions", [])), json.dumps(d["alpn"]) if "alpn" in d else None,
                   d.get("handshake"), json.dumps(headers, ensure_ascii=False) if headers else None,
                   json.dumps(d["body"]) if "body" in d else None, s.text(preview))
    write_csv(os.path.join(DATA, "sessions.csv.gz"),
              ["time", "src", "kind", "dst_port", "app", "host", "method", "path", "user_agent", "flags",
               "tls_versions", "alpn", "tls_handshake", "headers", "body", "preview"], rows())
    write_csv(os.path.join(DATA, "smtp.csv"),
              ["time", "src", "kind", "dst_port", "helo", "mail_from", "rcpt_to", "auth_mechanism", "other"],
              smtp)


# ---------------------------------------------------------------- results/tables/

TECHNIQUES = [
    # (name, what it is, table, SQL condition)
    ("dotenv", "Requests for .env secrets files", "sessions", "path LIKE '%.env%'"),
    ("mcp-hunting", "Looking for exposed MCP (Model Context Protocol) servers at /mcp or /sse", "sessions",
     "path GLOB '/mcp*' OR path GLOB '/sse*' OR path GLOB '*/mcp'"),
    ("alpn-sweep", "TLS ClientHello offering 5+ ALPN protocols, to see which one the server picks", "sessions",
     "detail LIKE '%\"alpn\"%' AND json_array_length(json_extract(detail, '$.alpn')) >= 5"),
    ("websiphon", "WebSiphon secrets scanner (user agent)", "sessions", "user_agent LIKE '%websiphon%'"),
    ("mglndd", "MGLNDD_<ip>_<port> banner sent to every port", "sessions", "preview LIKE 'MGLNDD%'"),
    ("nextjs-middleware-bypass", "Next.js middleware bypass, CVE-2025-29927 (x-middleware-subrequest header)",
     "sessions", "detail LIKE '%x-middleware-subrequest%'"),
    ("git-config", "Exposed /.git/config", "sessions", "path LIKE '%/.git/config%'"),
    ("redtail", "RedTail cryptominer spreader (libredtail-http user agent)", "sessions",
     "user_agent LIKE '%libredtail%'"),
    ("aws-credentials", "Exposed .aws/credentials", "sessions", "path LIKE '%.aws/credentials%'"),
    ("kubernetes-api", "Kubernetes API paths (/api/v1/pods, /apis/)", "sessions",
     "path LIKE '/api/v1/pods%' OR path LIKE '/apis/%'"),
    ("react-server-actions", "POSTs with a Next-Action header, the shape of React2Shell (CVE-2025-55182)",
     "sessions", "detail LIKE '%\"next-action\"%'"),
    ("vite-fs", "Vite dev-server file read through /@fs/ (CVE-2025-30208 family)", "sessions",
     "path LIKE '/@fs/%'"),
    ("runpod-jupyter", "RunPod and Jupyter config/secrets files", "sessions",
     "path LIKE '%runpod%' OR path LIKE '%.jupyter%'"),
    ("adb", "Android Debug Bridge CNXN handshake", "sessions", "preview LIKE 'CNXN%'"),
    ("x11", "X11 connection setup on 6000-6002", "sessions",
     "preview LIKE 'l\\x00\\x0b%' OR preview LIKE 'B\\x00\\x00\\x0b%'"),
    ("php-cgi-argument-injection", "PHP-CGI argument injection, CVE-2024-4577 (allow_url_include)", "sessions",
     "path LIKE '%allow_url_include%'"),
    ("docker-api", "Docker Engine API (/containers/json, /version on 2375)", "sessions",
     "path LIKE '/containers/json%' OR path LIKE '/v1.%/containers%' OR (path = '/version' AND dst_port = 2375)"),
    ("s7comm", "Siemens S7 (ISO-TSAP) on 102", "sessions", "dst_port = 102 AND preview LIKE '\\x03\\x00%'"),
    ("modbus", "Modbus/TCP on 502", "sessions", "dst_port = 502 AND preview IS NOT NULL"),
    ("ethernet-ip", "EtherNet/IP (CIP) on 44818", "sessions", "dst_port = 44818 AND preview IS NOT NULL"),
    ("dnp3", "DNP3 on 20000", "sessions", "dst_port = 20000 AND preview LIKE '\\x05d%'"),
    ("sglang-weights", "SGLang /update_weights_from_*: push new weights into an LLM server", "sessions",
     "path LIKE '%update_weights_from%'"),
    ("ollama-openai-api", "Ollama and OpenAI-compatible LLM APIs (/api/tags, /v1/models, ...)", "sessions",
     "path LIKE '/api/tags%' OR path LIKE '/api/generate%' OR path LIKE '/api/chat%' "
     "OR path LIKE '/v1/models%' OR path LIKE '/v1/chat/completions%'"),
    ("cgi-bin-traversal", "Apache cgi-bin path traversal, CVE-2021-41773/42013", "sessions",
     "path LIKE '/cgi-bin/%.%2e%' OR path LIKE '/cgi-bin/../%'"),
    ("sap-metadatauploader", "SAP NetWeaver Visual Composer upload, CVE-2025-31324", "sessions",
     "path LIKE '%metadatauploader%'"),
    ("jaws-shell", "JAWS DVR /shell?<command> downloader", "sessions", "path LIKE '/shell?%'"),
    ("krebsonsecurity-ua", "Botnet dropper whose user agent is 'KrebsOnSecurity'", "sessions",
     "user_agent LIKE '%KrebsOnSecurity%'"),
    ("literal-pwd", "Wordlist bug: a literal $(pwd) in the requested path", "sessions",
     "path LIKE '%$(pwd)%'"),
    ("ai-crawler-costume", "/z9x8c7v6b5-debug-trigger-<host>, sent with a different AI crawler user agent each time",
     "sessions", "path LIKE '/z9x8c7v6b5-debug-trigger%'"),
    ("upnp-addportmapping", "UPnP AddPortMapping over HTTP (asks a router to open a port)", "sessions",
     "detail LIKE '%AddPortMapping%'"),
    ("poop1234", "Next.js exploit tool sending x-nextjs-request-id: poop1234", "sessions",
     "detail LIKE '%poop1234%'"),
    ("ntp-monlist", "NTP mode-7 monlist request (amplification check)", "attempts",
     "proto = 'udp' AND dst_port = 123 AND info LIKE '\\x17\\x00\\x03%'"),
    ("bacnet", "BACnet on udp/47808", "attempts", "proto = 'udp' AND dst_port = 47808"),
    ("vxworks-wdb", "VxWorks WDB debug agent on udp/17185", "attempts", "proto = 'udp' AND dst_port = 17185"),
    ("gtp", "GTP-C echo request on udp/2123 (mobile network core)", "attempts",
     "proto = 'udp' AND dst_port = 2123 AND (info LIKE '2\\x01%' OR info LIKE '@\\x01%')"),
    ("censys-dht", "BitTorrent DHT ping whose node ID spells 'censysinspectscanner'", "attempts",
     "info LIKE '%censysinspect%'"),
]


def techniques(db, s):
    rows = []
    for name, what, table, cond in TECHNIQUES:
        sample = "path" if table == "sessions" else "info"
        hits, sources, first, last = db.execute(
            f"SELECT COUNT(*), COUNT(DISTINCT src_ip), MIN(ts), MAX(ts) FROM {table} WHERE {cond}").fetchone()
        example = db.execute(f"SELECT {sample} FROM {table} WHERE ({cond}) AND {sample} IS NOT NULL "
                             f"GROUP BY {sample} ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
        rows.append((name, what, hits, sources, first and iso(first), last and iso(last),
                     s.text(example[0])[:200] if example else None))
    rows.sort(key=lambda r: -r[3])
    write_csv(os.path.join(TABLES, "techniques.csv"),
              ["name", "what", "hits", "sources", "first_seen", "last_seen", "example"], rows)


def counted(path, header, counter, limit=None, extra=None):
    rows = []
    for key, (n, srcs) in sorted(counter.items(), key=lambda kv: -kv[1][0])[:limit]:
        rows.append((*key, n, len(srcs), *(extra(key) if extra else ())))
    write_csv(path, header, rows)
    return rows


def tables(db, s):
    first_seen = dict(db.execute(
        "SELECT src_ip, MIN(ts) FROM (SELECT src_ip, ts FROM attempts UNION ALL SELECT src_ip, ts FROM sessions) "
        "GROUP BY src_ip"))
    new_by_day = collections.Counter(day(t) for t in first_seen.values())
    daily = collections.defaultdict(lambda: collections.Counter())
    for d, proto, n, srcs in db.execute(
            "SELECT date(ts, 'unixepoch'), proto, COUNT(*), COUNT(DISTINCT src_ip) FROM attempts GROUP BY 1, 2"):
        daily[d][proto] = n
    for d, n in db.execute("SELECT date(ts, 'unixepoch'), COUNT(*) FROM sessions GROUP BY 1"):
        daily[d]["sessions"] = n
    for d, n in db.execute(
            "SELECT d, COUNT(DISTINCT src_ip) FROM (SELECT date(ts, 'unixepoch') d, src_ip FROM attempts "
            "UNION SELECT date(ts, 'unixepoch'), src_ip FROM sessions) GROUP BY d"):
        daily[d]["sources"] = n
    daily_rows = [(d, c["tcp"], c["udp"], c["icmp"], c["sessions"], c["sources"], new_by_day[d])
                  for d, c in sorted(daily.items())]
    write_csv(os.path.join(TABLES, "daily.csv"),
              ["day", "tcp_attempts", "udp_attempts", "icmp_attempts", "sessions", "sources", "new_sources"],
              daily_rows)

    ports = list(db.execute(
        "SELECT proto, dst_port, COUNT(*) n, COUNT(DISTINCT src_ip) FROM attempts WHERE dst_port IS NOT NULL "
        "GROUP BY 1, 2 ORDER BY 4 DESC"))
    spoke = collections.defaultdict(collections.Counter)
    for port, app, n in db.execute("SELECT dst_port, app, COUNT(*) FROM sessions GROUP BY 1, 2"):
        spoke[port][app] = n
    write_csv(os.path.join(TABLES, "ports.csv"),
              ["proto", "port", "attempts", "sources", "clients_spoke"],
              [(proto, port, n, srcs, " ".join(f"{a}:{c}" for a, c in spoke[port].most_common(4))
                if proto == "tcp" else None) for proto, port, n, srcs in ports[:500]])

    protos = list(db.execute(
        "SELECT app, COUNT(*), COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_port) FROM sessions GROUP BY 1 ORDER BY 2 DESC"))
    write_csv(os.path.join(TABLES, "protocols.csv"), ["app", "sessions", "sources", "ports"], protos)

    kinds = list(db.execute("""
        SELECT COALESCE(i.kind, 'isp'), COUNT(*), SUM(a), SUM(s) FROM (
            SELECT src_ip, SUM(a) a, SUM(s) s FROM (
                SELECT src_ip, 1 a, 0 s FROM attempts UNION ALL SELECT src_ip, 0, 1 FROM sessions)
            GROUP BY src_ip) x LEFT JOIN ip_info i ON i.ip = x.src_ip GROUP BY 1 ORDER BY 2 DESC"""))
    write_csv(os.path.join(TABLES, "source_kinds.csv"), ["kind", "sources", "attempts", "sessions"], kinds)

    per_src = """SELECT src_ip, COUNT(*) n FROM attempts GROUP BY src_ip"""
    countries = list(db.execute(f"""
        SELECT COALESCE(i.cc, '??'), COUNT(*), SUM(x.n),
               SUM(i.kind = 'scanner'), SUM(i.kind = 'hosting'), SUM(i.kind = 'isp')
        FROM ({per_src}) x LEFT JOIN ip_info i ON i.ip = x.src_ip GROUP BY 1 ORDER BY 2 DESC"""))
    write_csv(os.path.join(TABLES, "countries.csv"),
              ["country", "sources", "attempts", "scanner_sources", "hosting_sources", "isp_sources"], countries)

    networks = list(db.execute(f"""
        SELECT i.asn, i.as_name, COUNT(*), SUM(x.n),
               SUM(i.kind = 'scanner'), SUM(i.kind = 'hosting'), SUM(i.kind = 'isp')
        FROM ({per_src}) x JOIN ip_info i ON i.ip = x.src_ip GROUP BY i.asn ORDER BY 3 DESC LIMIT 300"""))
    write_csv(os.path.join(TABLES, "networks.csv"),
              ["asn", "as_name", "sources", "attempts", "scanner_sources", "hosting_sources",
               "isp_sources"], networks)

    paths = collections.defaultdict(lambda: [0, set()])
    agents = collections.defaultdict(lambda: [0, set()])
    hosts = collections.defaultdict(lambda: [0, set()])
    for ip, app, domain, method, path, ua in db.execute(
            "SELECT src_ip, app, domain, method, path, user_agent FROM sessions WHERE app IN ('http', 'https', 'tls')"):
        if path is not None:
            p = paths[(method, s.text(path))]
            p[0] += 1
            p[1].add(ip)
        if ua:
            a = agents[(s.text(ua),)]
            a[0] += 1
            a[1].add(ip)
        if domain:
            h = hosts[(s.text(domain).lower(), app)]
            h[0] += 1
            h[1].add(ip)
    counted(os.path.join(TABLES, "http_paths.csv"), ["method", "path", "requests", "sources"], paths, 2000)
    counted(os.path.join(TABLES, "user_agents.csv"), ["user_agent", "requests", "sources"], agents, 1000)

    def watched(host):
        return bool(WATCHED_HOST.fullmatch(host))
    host_rows = sorted(hosts.items(), key=lambda kv: -kv[1][0])
    write_csv(os.path.join(TABLES, "watched_hostnames.csv"),
              ["host", "app", "requests", "sources", "isp_sources"],
              [(h, app, n, len(ips), sum(1 for ip in ips if s.kind(ip) == "isp"))
               for (h, app), (n, ips) in host_rows if watched(h)])
    write_csv(os.path.join(TABLES, "other_hostnames.csv"), ["host", "app", "requests", "sources"],
              [(h, app, n, len(ips)) for (h, app), (n, ips) in host_rows if not watched(h)][:1000])
    return daily_rows, ports, countries


# ---------------------------------------------------------------- results/charts/

CHART_CSS = """
  .bg { fill: #fcfcfb } .bar { fill: #2a78d6 } .ink { fill: #0b0b0b } .ink2 { fill: #52514e }
  .muted { fill: #898781 } .grid { stroke: #e1e0d9 } .axis { stroke: #c3c2b7 }
  @media (prefers-color-scheme: dark) {
    .bg { fill: #1a1a19 } .bar { fill: #3987e5 } .ink { fill: #f0efec } .ink2 { fill: #c3c2b7 }
    .grid { stroke: #2c2c2a } .axis { stroke: #383835 }
  }
  text { font: 12px -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif }
  .title { font-size: 15px; font-weight: 600 } .sub { font-size: 12px }
  .bar:hover { opacity: .8 }
"""


def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def bar_path(x, y, w, h, horizontal):
    """A bar with 4px rounded corners at the data end only (the baseline end stays square)."""
    r = min(4, w / 2, h / 2)
    if horizontal:   # baseline on the left
        return (f"M{x},{y} h{w - r} a{r},{r} 0 0 1 {r},{r} v{h - 2 * r} a{r},{r} 0 0 1 {-r},{r} "
                f"h{-(w - r)} z")
    return (f"M{x},{y + h} v{-(h - r)} a{r},{r} 0 0 1 {r},{-r} h{w - 2 * r} a{r},{r} 0 0 1 {r},{r} "
            f"v{h - r} z")


def nice_max(v):
    for step in (1, 2, 2.5, 5):
        for mag in range(0, 12):
            top = step * 10 ** mag
            if top >= v:
                return top, top / (4 if step in (1, 2) else 5)
    return v, v / 4


def fmt(n):
    return f"{n / 1000:g}k" if n >= 1000 else f"{n:g}"


def column_chart(path, title, sub, items, note):
    W, H, L, R, T, B = 760, 340, 56, 16, 70, 46
    top, step = nice_max(max(v for _, v, _ in items))
    pw, ph = W - L - R, H - T - B
    slot = pw / len(items)
    bw = max(4, slot - 2 - slot * 0.3)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           f'role="img" aria-label="{esc(title)}"><style>{CHART_CSS}</style>',
           f'<rect class="bg" width="{W}" height="{H}" rx="8"/>',
           f'<text class="ink title" x="{L}" y="28">{esc(title)}</text>',
           f'<text class="ink2 sub" x="{L}" y="48">{esc(sub)}</text>']
    v = 0
    while v <= top + 1e-9:
        y = T + ph - ph * v / top
        out.append(f'<line class="{"axis" if v == 0 else "grid"}" x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text class="muted" x="{L - 8}" y="{y + 4:.1f}" text-anchor="end">{fmt(v)}</text>')
        v += step
    for i, (label, value, tip) in enumerate(items):
        x = L + i * slot + (slot - bw) / 2
        h = max(1, ph * value / top)
        out.append(f'<path class="bar" d="{bar_path(round(x, 1), round(T + ph - h, 1), round(bw, 1), round(h, 1), False)}">'
                   f'<title>{esc(tip)}</title></path>')
        if label:
            out.append(f'<text class="muted" x="{x + bw / 2:.1f}" y="{T + ph + 18}" text-anchor="middle">{esc(label)}</text>')
    out.append(f'<text class="muted" x="{L}" y="{H - 8}">{esc(note)}</text></svg>')
    with open(path, "w") as f:
        f.write("\n".join(out))
    print(f"  {os.path.relpath(path, ROOT)}")


def bar_chart(path, title, sub, items, note):
    row, L, R, T, B, W = 26, 190, 70, 70, 34, 760
    H = T + row * len(items) + B
    top = max(v for _, v, _ in items)
    pw = W - L - R
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           f'role="img" aria-label="{esc(title)}"><style>{CHART_CSS}</style>',
           f'<rect class="bg" width="{W}" height="{H}" rx="8"/>',
           f'<text class="ink title" x="16" y="28">{esc(title)}</text>',
           f'<text class="ink2 sub" x="16" y="48">{esc(sub)}</text>',
           f'<line class="axis" x1="{L}" x2="{L}" y1="{T - 4}" y2="{T + row * len(items)}"/>']
    for i, (label, value, tip) in enumerate(items):
        y = T + i * row
        w = max(1, pw * value / top)
        out.append(f'<text class="ink2" x="{L - 10}" y="{y + row / 2 + 4}" text-anchor="end">{esc(label)}</text>')
        out.append(f'<path class="bar" d="{bar_path(L, y + 5, round(w, 1), row - 10, True)}"><title>{esc(tip)}</title></path>')
        out.append(f'<text class="ink" x="{L + w + 8:.1f}" y="{y + row / 2 + 4}">{value:,}</text>')
    out.append(f'<text class="muted" x="16" y="{H - 10}">{esc(note)}</text></svg>')
    with open(path, "w") as f:
        f.write("\n".join(out))
    print(f"  {os.path.relpath(path, ROOT)}")


PORT_NAMES = {22: "ssh", 23: "telnet", 80: "http", 443: "https", 3389: "rdp", 8080: "http-alt", 445: "smb",
              8443: "https-alt", 21: "ftp", 25: "smtp", 3306: "mysql", 5432: "postgres", 6379: "redis",
              1433: "mssql", 5900: "vnc", 8000: "http-alt", 8888: "http-alt", 2222: "ssh-alt", 81: "http-alt",
              8081: "http-alt", 5060: "sip", 53: "dns", 123: "ntp", 161: "snmp", 1900: "ssdp", 9200: "elastic",
              2375: "docker", 6443: "k8s", 11211: "memcached", 27017: "mongodb", 102: "s7", 502: "modbus",
              110: "pop3", 143: "imap", 993: "imaps", 995: "pop3s", 587: "submission", 465: "smtps",
              5555: "adb", 7547: "tr-069", 37215: "huawei", 3128: "proxy", 1080: "socks",
              8008: "http-alt", 10000: "webmin"}


def charts(daily_rows, ports, countries, first_full, last_full):
    full = [r for r in daily_rows if first_full <= r[0] <= last_full]
    column_chart(
        os.path.join(CHARTS, "daily_sources.svg"), "Distinct source addresses per day",
        f"Every address that sent a packet to 20.119.52.2, {full[0][0]} to {full[-1][0]} (UTC, full days only)",
        [(r[0][5:] if i % 2 == 0 else "", r[5], f"{r[0]}: {r[5]:,} sources, {r[6]:,} never seen before")
         for i, r in enumerate(full)],
        "Source: results/tables/daily.csv")
    tcp = [p for p in ports if p[0] == "tcp"][:15]
    bar_chart(
        os.path.join(CHARTS, "top_tcp_ports.svg"), "Most-probed TCP ports",
        "Distinct source addresses that sent a SYN to each port, whole capture",
        [(f"{port} {PORT_NAMES.get(port, '')}".strip(), srcs, f"tcp/{port}: {srcs:,} sources, {n:,} SYNs")
         for _, port, n, srcs in tcp],
        "Source: results/tables/ports.csv")
    top = [c for c in countries if c[0] != "??"][:12]
    bar_chart(
        os.path.join(CHARTS, "top_countries.svg"), "Where the traffic comes from",
        "Distinct source addresses per country (Team Cymru registry data), whole capture",
        [(cc, srcs, f"{cc}: {srcs:,} sources, {n:,} packets") for cc, srcs, n, *_ in top],
        "Source: results/tables/countries.csv. Registry country, not where a person sits.")


def main():
    db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    for d in (DATA, TABLES, CHARTS):
        os.makedirs(d, exist_ok=True)
    s = Sanitiser(dict(db.execute("SELECT ip, kind FROM ip_info")))
    # Name redacted labels in order of first appearance, so the names are stable for a given database.
    for (domain,) in db.execute("SELECT domain FROM sessions WHERE domain LIKE '%.download' "
                                "GROUP BY lower(domain) ORDER BY MIN(ts)"):
        s.text(domain)
    print("data/")
    export_sources(db, s)
    export_attempts(db, s)
    export_sessions(db, s)
    print("results/")
    techniques(db, s)
    daily_rows, ports, countries = tables(db, s)
    days = [r[0] for r in daily_rows]
    charts(daily_rows, ports, countries, days[1], days[-2])


if __name__ == "__main__":
    main()
