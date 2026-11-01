"""Read-only dashboard, bound to the box's loopback interface only.

View it through an SSH tunnel:
    ssh -N -L 8088:127.0.0.1:8088 <user>@20.119.52.2
then open http://localhost:8088 locally.
"""
import collections
import ipaddress
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common import connect, log

BIND = ("127.0.0.1", int(os.environ.get("WHOHIT_DASH_PORT", "8088")))
INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
WATCH_FILE = os.environ.get("WHOHIT_WATCH", "/etc/whohit/watch.txt")
# range -> (seconds back, timeline bucket seconds)
RANGES = {"1h": (3600, 60), "24h": (86400, 1800), "7d": (7 * 86400, 3600),
          "30d": (30 * 86400, 6 * 3600), "all": (None, 86400)}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def split_set(value, sep=r"[ ,]+"):
    return sorted({v for v in re.split(sep, value or "") if v})


def short_net(as_name):
    """'AMAZON-02 - Amazon.com, Inc., US' -> 'Amazon.com, Inc.'"""
    if not as_name:
        return None
    return re.sub(r",\s*[A-Z]{2}$", "", as_name.split(" - ", 1)[-1]).strip()[:60]


def watchlist():
    try:
        with open(WATCH_FILE) as f:
            return [line.strip().lower().strip(".") for line in f
                    if line.strip() and not line.lstrip().startswith("#")]
    except OSError:
        return []


def watched_parent(domain, suffixes):
    return next((s for s in suffixes if domain == s or domain.endswith("." + s)), None)


def watch_sql(suffixes):
    """SQL condition matching a watched domain or any of its subdomains."""
    if not suffixes:
        return "0", []
    return " OR ".join(["domain = ? OR domain LIKE ?"] * len(suffixes)), \
        [a for s in suffixes for a in (s, "%." + s)]


class Query:
    def __init__(self, params):
        self.p = {k: v[0] for k, v in params.items()}
        self.range = self.p.get("range") if self.p.get("range") in RANGES else "24h"
        back, self.bucket = RANGES[self.range]
        self.since = time.time() - back if back else 0
        self.hide_ssh = self.p.get("ssh") != "1"
        self.bare = self.p.get("bare") == "1"
        self.ssh_clause = " AND dst_port IS NOT 22" if self.hide_ssh else ""
        # Unlabelled addresses stay visible: only drop what we know is cloud or a scanner.
        self.src_clause = (" AND src_ip NOT IN (SELECT ip FROM ip_info WHERE kind IN ('scanner', 'hosting'))"
                           if self.p.get("quiet") == "1" else "")


def stats(q):
    db = connect(readonly=True)
    one = lambda sql, *args: db.execute(sql, args).fetchone()[0]  # noqa: E731
    sc, since = q.src_clause, q.since
    pc = q.ssh_clause + sc
    suffixes = watchlist()

    totals = {
        "attempts": one(f"SELECT COUNT(*) FROM attempts WHERE ts >= ?{pc}", since),
        "sources": one(f"SELECT COUNT(DISTINCT src_ip) FROM attempts WHERE ts >= ?{pc}", since),
        "ports": one(f"SELECT COUNT(DISTINCT proto || dst_port) FROM attempts "
                     f"WHERE ts >= ? AND dst_port IS NOT NULL{pc}", since),
        "sessions": one(f"SELECT COUNT(*) FROM sessions WHERE ts >= ?{sc}", since),
        "first_seen": one("SELECT MIN(ts) FROM attempts"),
        "labelled": one("SELECT COUNT(*) FROM ip_info"),
    }

    # One row per (domain, source) so every domain can say how many sources look like people.
    domains, groups = {}, {s: {"suffix": s, "hits": 0, "ips": set(), "people": set(), "first": None,
                               "last": None, "via": set(), "flags": set(), "hosts": []} for s in suffixes}
    for d, ip, n, first, last, apps, ports, flags, kind, as_name, reason in db.execute(f"""
            SELECT x.domain, x.src_ip, COUNT(*), MIN(x.ts), MAX(x.ts), GROUP_CONCAT(DISTINCT x.app),
                   GROUP_CONCAT(DISTINCT x.dst_port), GROUP_CONCAT(DISTINCT x.flags), i.kind, i.as_name, i.reason
            FROM (SELECT domain, src_ip, ts, app, dst_port, flags FROM sessions
                  WHERE ts >= ? AND domain IS NOT NULL{sc}
                  UNION ALL
                  SELECT domain, src_ip, ts, 'dns', dst_port, NULL FROM attempts
                  WHERE ts >= ? AND domain IS NOT NULL{sc}) x
            LEFT JOIN ip_info i ON i.ip = x.src_ip
            GROUP BY x.domain, x.src_ip""", (since, since)):
        if (is_ip(d) and not q.bare) or "." not in d.strip("."):  # root / single-label DNS probes
            continue
        e = domains.setdefault(d, {"domain": d, "hits": 0, "ips": 0, "people": 0, "first": first, "last": last,
                                   "via": set(), "ports": set(), "flags": set(), "top": None, "requests": []})
        e["hits"] += n
        e["ips"] += 1
        e["people"] += kind == "isp"
        e["first"], e["last"] = min(e["first"], first), max(e["last"], last)
        e["via"].update(split_set(apps))
        e["ports"].update(int(p) for p in split_set(ports))
        e["flags"].update(split_set(flags))
        if e["top"] is None or n > e["top"]["n"]:
            e["top"] = {"ip": ip, "n": n, "kind": kind or "unknown", "net": short_net(as_name), "reason": reason}
        parent = watched_parent(d, suffixes)
        if parent:
            g = groups[parent]
            g["hits"] += n
            g["ips"].add(ip)
            if kind == "isp":
                g["people"].add(ip)
            g["first"] = min(g["first"] or first, first)
            g["last"] = max(g["last"] or last, last)
            g["via"].update(split_set(apps))
            g["flags"].update(split_set(flags))

    rank = lambda e: (-e["people"], -e["hits"])  # noqa: E731
    mine = [e for e in domains.values() if watched_parent(e["domain"], suffixes)]
    others = sorted((e for e in domains.values() if not watched_parent(e["domain"], suffixes)),
                    key=lambda e: -e["hits"])[:300]
    by_domain = {e["domain"]: e for e in mine + others}
    if by_domain:
        marks = ",".join("?" * len(by_domain))
        for d, method, path, n in db.execute(f"""
                SELECT domain, method, path, COUNT(*) FROM sessions
                WHERE ts >= ? AND path IS NOT NULL AND domain IN ({marks}){sc}
                GROUP BY domain, method, path ORDER BY COUNT(*) DESC""", (since, *by_domain)):
            if len(by_domain[d]["requests"]) < 5:
                by_domain[d]["requests"].append({"method": method, "path": path, "n": n})
    for e in by_domain.values():
        e["via"], e["ports"], e["flags"] = sorted(e["via"]), sorted(e["ports"]), sorted(e["flags"])
    for e in sorted(mine, key=rank):
        groups[watched_parent(e["domain"], suffixes)]["hosts"].append(e)
    mine_groups = []
    for g in groups.values():
        g.update(ips=len(g["ips"]), people=len(g["people"]), via=sorted(g["via"]), flags=sorted(g["flags"]))
        mine_groups.append(g)
    mine_groups.sort(key=rank)
    wsql, wargs = watch_sql(suffixes)
    mine_sources = (f"SELECT src_ip FROM sessions WHERE ts >= ? AND ({wsql}){sc} "
                    f"UNION SELECT src_ip FROM attempts WHERE ts >= ? AND ({wsql}){sc}")
    margs = (since, *wargs, since, *wargs)
    totals.update(
        mine_hits=sum(g["hits"] for g in mine_groups),
        mine_ips=one(f"SELECT COUNT(*) FROM ({mine_sources})", *margs),
        mine_people=one(f"SELECT COUNT(*) FROM ({mine_sources}) "
                        "WHERE src_ip IN (SELECT ip FROM ip_info WHERE kind = 'isp')", *margs),
        mine_hosts=len(mine),
        mine_flagged=sum(1 for e in mine if e["flags"]),
        watch=suffixes,
    )

    spoke = {}
    for port, app, n in db.execute(
            f"SELECT dst_port, app, COUNT(*) FROM sessions WHERE ts >= ?{sc} GROUP BY dst_port, app "
            "ORDER BY COUNT(*) DESC", (since,)):
        spoke.setdefault(port, []).append({"app": app, "n": n})
    ports = [{"proto": proto, "port": port, "attempts": n, "ips": ips, "last": last,
              "spoke": spoke.get(port, []) if proto == "tcp" else []}
             for proto, port, n, ips, last in db.execute(f"""
                SELECT proto, dst_port, COUNT(*), COUNT(DISTINCT src_ip), MAX(ts) FROM attempts
                WHERE ts >= ?{pc} GROUP BY proto, dst_port ORDER BY COUNT(*) DESC LIMIT 200""", (since,))]

    sources = [{"ip": ip, "attempts": n, "ports": nports, "last": last, "domains": [], "net": short_net(as_name),
                "cc": cc, "rdns": rdns, "kind": kind or "unknown", "reason": reason}
               for ip, n, nports, last, as_name, cc, rdns, kind, reason in db.execute(f"""
                SELECT src_ip, COUNT(*), COUNT(DISTINCT dst_port), MAX(ts), i.as_name, i.cc, i.rdns, i.kind, i.reason
                FROM attempts LEFT JOIN ip_info i ON i.ip = src_ip
                WHERE ts >= ?{pc} GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 100""", (since,))]
    by_ip = {s["ip"]: s for s in sources}
    if by_ip:
        marks = ",".join("?" * len(by_ip))
        for ip, ds in db.execute(f"""
                SELECT src_ip, GROUP_CONCAT(DISTINCT domain) FROM sessions
                WHERE ts >= ? AND domain IS NOT NULL AND src_ip IN ({marks}) GROUP BY src_ip""",
                                 (since, *by_ip)):
            by_ip[ip]["domains"] = split_set(ds, ",")[:5]

    start = since or (totals["first_seen"] or time.time())
    bucket = q.bucket
    timeline = {
        "bucket": bucket, "start": int(start // bucket) * bucket,
        "attempts": dict(db.execute(f"""
            SELECT CAST(ts / ? AS INTEGER) * ?, COUNT(*) FROM attempts
            WHERE ts >= ?{pc} GROUP BY 1""", (bucket, bucket, since)).fetchall()),
        "mine": dict(db.execute(f"""
            SELECT CAST(ts / ? AS INTEGER) * ?, COUNT(*) FROM (
                SELECT ts FROM sessions WHERE ts >= ? AND ({wsql}){sc}
                UNION ALL SELECT ts FROM attempts WHERE ts >= ? AND ({wsql}){sc})
            GROUP BY 1""", (bucket, bucket, since, *wargs, since, *wargs)).fetchall()),
    }
    db.close()
    return {"now": time.time(), "range": q.range, "totals": totals, "timeline": timeline,
            "mine": mine_groups, "others": others, "ports": ports, "sources": sources}


def events(q):
    """Latest raw rows, optionally narrowed to one domain / suffix / port / source IP / app."""
    kind = "attempts" if q.p.get("kind") == "attempts" else "sessions"
    where, args = ["ts >= ?"], [q.since]
    for field in ("domain", "src_ip", "app"):
        if q.p.get(field) and not (kind == "attempts" and field == "app"):
            where.append(f"{field} = ?")
            args.append(q.p[field])
    if q.p.get("suffix"):
        where.append("(domain = ? OR domain LIKE ?)")
        args += [q.p["suffix"], "%." + q.p["suffix"]]
    if q.p.get("port", "").isdigit():
        where.append("dst_port = ?")
        args.append(int(q.p["port"]))
    if kind == "attempts" and q.hide_ssh and not q.p.get("port"):
        where.append("dst_port IS NOT 22")
    limit = min(int(q.p["limit"]) if q.p.get("limit", "").isdigit() else 200, 1000)
    db = connect(readonly=True)
    db.row_factory = lambda cur, row: {c[0]: v for c, v in zip(cur.description, row)}
    rows = db.execute(f"""
        SELECT e.*, i.as_name, i.cc, i.rdns, COALESCE(i.kind, 'unknown') AS kind, i.reason
        FROM {kind} e LEFT JOIN ip_info i ON i.ip = e.src_ip
        WHERE {' AND '.join(where)}{q.src_clause} ORDER BY ts DESC LIMIT ?""", (*args, limit)).fetchall()
    db.close()
    for r in rows:
        r["net"] = short_net(r.pop("as_name"))
        if r.get("detail"):
            r["detail"] = json.loads(r["detail"])
    return {"kind": kind, "rows": rows}


class Handler(BaseHTTPRequestHandler):
    server_version = "whohit"

    def do_GET(self):
        # Only answer to localhost names: blocks DNS rebinding through the tunnel.
        host = (self.headers.get("Host") or "").lower()
        host = host[1:].split("]")[0] if host.startswith("[") else host.rsplit(":", 1)[0]
        if host not in LOCAL_HOSTS:
            return self.reply(403, b"forbidden\n", "text/plain")
        url = urlparse(self.path)
        q = Query(parse_qs(url.query))
        try:
            if url.path == "/":
                with open(INDEX, "rb") as f:
                    return self.reply(200, f.read(), "text/html; charset=utf-8")
            if url.path == "/api/stats":
                return self.reply(200, json.dumps(stats(q)).encode(), "application/json")
            if url.path == "/api/events":
                return self.reply(200, json.dumps(events(q)).encode(), "application/json")
        except Exception as e:  # keep serving; show the error instead of a dropped connection
            log(f"{url.path}: {e!r}")
            return self.reply(500, json.dumps({"error": str(e)}).encode(), "application/json")
        self.reply(404, b"not found\n", "text/plain")

    def reply(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    server = ThreadingHTTPServer(BIND, Handler)
    server.daemon_threads = True
    log(f"dashboard on http://{BIND[0]}:{BIND[1]}")
    server.serve_forever()


if __name__ == "__main__":
    main()
