"""Label every source IP with who owns it, so people stand out from scanners.

For each new source address: AS number, network name and country (Team
Cymru's bulk whois), reverse DNS, and a coarse kind:

  scanner  says it is a scanner or crawler (User-Agent, reverse DNS or network name),
           or behaves like one: touched several ports, fetched robots.txt, probed for
           an open proxy, or probed DNS server details
  hosting  a cloud or hosting network, where scanners and bots live
  isp      everything else: home, mobile and office connections, where people are,
           but also small hosting companies the name list misses

Generic HTTP libraries (curl, python-requests, Go) are deliberately not treated
as scanners: an old script or app still calling a domain is exactly what we
are looking for.
"""
import concurrent.futures
import ipaddress
import re
import socket
import sqlite3
import time

from common import connect, log

CYMRU = ("whois.cymru.com", 43)
BATCH = 500
INTERVAL = 30
SCANNER_PORTS = 5   # a visitor uses one or two ports; a scanner sweeps
DNS_PROBES = ("version.bind", "hostname.bind", "id.server", "version.server", ".")

SCANNER_UA = re.compile(
    r"zgrab|masscan|nmap|nuclei|censys|palo alto networks|expanse|shadowserver|softsec\.ruhr-uni|"
    r"mrtscan|visionheight|webatla|scrapy|headless|internet-measurement|modat|l9explore|odin|"
    r"ips-agent|crawler|spider|scanner|bot\b|\+https?://", re.I)
SCANNER_RDNS = re.compile(
    r"censys|shodan|shadowserver|binaryedge|internet-measurement|sba-research|ruhr-uni|stretchoid|"
    r"onyphe|criminalip|leakix|recyber|alphastrike|driftnet|fwdproxy|security|scan|probe|research|crawl", re.I)
SCANNER_NET = re.compile(
    r"censys|shadowserver|palo alto|internet-measurement|recyber|onyphe|stretchoid|alphastrike|"
    r"driftnet|bitsight|binaryedge|shodan|facebook|kaspersky", re.I)  # Meta's link-preview fetchers
HOSTING_NET = re.compile(
    r"amazon|google(?![- ]fiber)|microsoft|digitalocean|ovh|hetzner|tencent|alibaba|aliyun|huawei|"
    r"hwclouds|cloudflare|linode|akamai|vultr|choopa|contabo|m247|leaseweb|scaleway|ionos|hostinger|"
    r"oracle|\bibm\b|kamatera|hostwinds|colocrossing|psychz|sharktech|ucloud|cdsc|pfcloud|techties|"
    r"alsycon|gthost|eonscope|secureend|cloud|host|server|datacent|\bvps\b|dedicated|colocation", re.I)


def cymru(ips):
    """{ip: (asn, as_name, country)} from Team Cymru's bulk whois."""
    with socket.create_connection(CYMRU, timeout=60) as s:
        s.sendall(("begin\nverbose\n" + "\n".join(ips) + "\nend\n").encode())
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    out = {}
    for line in data.decode("utf-8", "replace").splitlines()[1:]:
        f = [x.strip() for x in line.split("|")]
        if len(f) >= 7:
            out[f[1]] = (int(f[0]) if f[0].isdigit() else None, f[6][:120] or None, f[3][:2] or None)
    return out


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0][:253]
    except (OSError, UnicodeError):
        return None


def classify(as_name, rdns_name, ua_reason):
    if ua_reason:
        return "scanner", ua_reason
    if rdns_name and SCANNER_RDNS.search(rdns_name):
        return "scanner", f"reverse DNS {rdns_name}"
    if as_name and SCANNER_NET.search(as_name):
        return "scanner", f"network {as_name}"
    if as_name and HOSTING_NET.search(as_name):
        return "hosting", None
    return "isp", None


def behaviour(db, ips):
    """{ip: reason} for addresses whose own traffic gives them away as scanners."""
    reasons = {}
    ips = list(ips)
    probes = ",".join("?" * len(DNS_PROBES))
    for i in range(0, len(ips), BATCH):
        chunk = ips[i:i + BATCH]
        marks = ",".join("?" * len(chunk))
        for ip, n in db.execute(f"""SELECT src_ip, COUNT(DISTINCT dst_port) FROM attempts WHERE src_ip IN ({marks})
                                    GROUP BY src_ip HAVING COUNT(DISTINCT dst_port) >= ?""", (*chunk, SCANNER_PORTS)):
            reasons.setdefault(ip, f"touched {n} different ports")
        for ip, what in db.execute(f"""SELECT src_ip, MIN(method || ' ' || path) FROM sessions WHERE src_ip IN ({marks})
                                       AND (method = 'CONNECT' OR path LIKE 'http://%' OR path LIKE 'https://%')
                                       GROUP BY src_ip""", chunk):
            reasons.setdefault(ip, f"open-proxy probe: {what[:80]}")
        for (ip,) in db.execute(f"SELECT DISTINCT src_ip FROM sessions WHERE src_ip IN ({marks}) "
                                "AND path = '/robots.txt'", chunk):
            reasons.setdefault(ip, "fetched robots.txt (a crawler)")
        for ip, d in db.execute(f"""SELECT src_ip, MIN(domain) FROM (
                                        SELECT src_ip, domain, info FROM attempts WHERE src_ip IN ({marks})
                                        UNION ALL SELECT src_ip, domain, method FROM sessions
                                        WHERE src_ip IN ({marks}) AND app = 'dns')
                                    WHERE domain IN ({probes}) OR info LIKE '%ANY%' GROUP BY src_ip""",
                                (*chunk, *chunk, *DNS_PROBES)):
            reasons.setdefault(ip, f"DNS server probe: {d}")
    return reasons


def mark_scanners(db, reasons):
    with db:
        db.executemany("UPDATE ip_info SET kind = 'scanner', reason = ?, updated = ? "
                       "WHERE ip = ? AND kind != 'scanner'",
                       [(r, time.time(), ip) for ip, r in reasons.items()])


def relabel_all(db):
    """Apply the current rules to every address already labelled (rules change over time)."""
    rows = db.execute("SELECT ip, as_name, rdns FROM ip_info WHERE kind != 'scanner'").fetchall()
    changed = {}
    with db:
        for ip, as_name, rdns_name in rows:
            kind, reason = classify(as_name, rdns_name, None)
            if db.execute(
                    "UPDATE ip_info SET kind = ?, reason = ?, updated = ? WHERE ip = ? AND kind != ?",
                    (kind, reason, time.time(), ip, kind)).rowcount:
                changed[ip] = kind
    reasons = behaviour(db, [ip for ip, _, _ in rows])
    mark_scanners(db, reasons)
    log(f"relabelled: {len(changed)} by network/rDNS, {len(reasons)} by behaviour")


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def cycle(db, pool):
    meta = dict(db.execute("SELECT key, value FROM meta WHERE key LIKE 'enrich_%'").fetchall())
    last_a, last_s = int(meta.get("enrich_attempt_id", 0)), int(meta.get("enrich_session_id", 0))
    max_a = db.execute("SELECT COALESCE(MAX(id), 0) FROM attempts").fetchone()[0]
    max_s = db.execute("SELECT COALESCE(MAX(id), 0) FROM sessions").fetchone()[0]

    recent = {ip for (ip,) in db.execute(
        "SELECT src_ip FROM attempts WHERE id > ? AND id <= ? UNION SELECT src_ip FROM sessions WHERE id > ? AND id <= ?",
        (last_a, max_a, last_s, max_s))}
    ua_reasons = {}
    for ip, ua in db.execute("SELECT src_ip, user_agent FROM sessions WHERE id > ? AND id <= ? "
                             "AND user_agent IS NOT NULL", (last_s, max_s)):
        if ip not in ua_reasons and SCANNER_UA.search(ua):
            ua_reasons[ip] = f"user agent {ua[:100]}"
    reasons = {**behaviour(db, recent), **ua_reasons}

    new = [ip for (ip,) in db.execute("""
        SELECT src_ip FROM attempts WHERE id > ? AND id <= ?
        UNION SELECT src_ip FROM sessions WHERE id > ? AND id <= ?
        EXCEPT SELECT ip FROM ip_info""", (last_a, max_a, last_s, max_s)) if is_public(ip)]
    for i in range(0, len(new), BATCH):
        batch = new[i:i + BATCH]
        owners = cymru(batch)
        names = dict(zip(batch, pool.map(rdns, batch)))
        rows = []
        for ip in batch:
            asn, as_name, cc = owners.get(ip, (None, None, None))
            kind, reason = classify(as_name, names[ip], reasons.get(ip))
            rows.append((ip, asn, as_name, cc, names[ip], kind, reason, time.time()))
        with db:
            db.executemany("INSERT OR REPLACE INTO ip_info VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)

    mark_scanners(db, reasons)  # known addresses that have since given themselves away
    with db:
        db.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                       [("enrich_attempt_id", str(max_a)), ("enrich_session_id", str(max_s))])
    if new:
        log(f"enriched {len(new)} new source addresses")


def main():
    db = connect()
    pool = concurrent.futures.ThreadPoolExecutor(32)
    log("enriching source addresses")
    relabel_all(db)
    while True:
        try:
            cycle(db, pool)
        except (OSError, sqlite3.Error) as e:
            log(f"enrich cycle failed, will retry: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
