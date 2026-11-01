"""Shared pieces: database location and schema, a batching writer, logging."""
import os
import queue
import sqlite3
import struct
import sys
import threading
import time

DB_PATH = os.environ.get("WHOHIT_DB", "/var/lib/whohit/whohit.db")

SCHEMA = """
-- One row per inbound connection attempt seen on the wire (sniffer.py).
CREATE TABLE IF NOT EXISTS attempts (
    id       INTEGER PRIMARY KEY,
    ts       REAL    NOT NULL,
    src_ip   TEXT    NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,            -- NULL for ICMP
    proto    TEXT    NOT NULL,   -- tcp | udp | icmp
    domain   TEXT,               -- DNS query name, when the packet is a DNS query
    info     TEXT                -- short description of a UDP/ICMP payload
);
CREATE INDEX IF NOT EXISTS attempts_ts   ON attempts(ts);
CREATE INDEX IF NOT EXISTS attempts_port ON attempts(dst_port, proto);
CREATE INDEX IF NOT EXISTS attempts_src  ON attempts(src_ip);

-- One row per TCP connection the catch-all listener handled (listener.py).
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    ts         REAL    NOT NULL,
    src_ip     TEXT    NOT NULL,
    src_port   INTEGER,
    dst_port   INTEGER NOT NULL,
    app        TEXT    NOT NULL,  -- http | https | tls | smtp | ssh | rdp | ... | silent | unknown
    domain     TEXT,              -- HTTP Host, TLS SNI, SMTP recipient domain or DNS-over-TCP name
    method     TEXT,
    path       TEXT,
    user_agent TEXT,
    flags      TEXT,              -- space separated signals of real use, see listener.py
    detail     TEXT,              -- JSON: headers (credentials redacted), ALPN, SMTP envelope, ...
    preview    TEXT               -- first bytes the client sent, escaped (non-HTTP only)
);
CREATE INDEX IF NOT EXISTS sessions_ts     ON sessions(ts);
CREATE INDEX IF NOT EXISTS sessions_domain ON sessions(domain);
CREATE INDEX IF NOT EXISTS sessions_port   ON sessions(dst_port);
CREATE INDEX IF NOT EXISTS sessions_src    ON sessions(src_ip);

-- Who each source IP belongs to (enrich.py), so people stand out from scanners.
CREATE TABLE IF NOT EXISTS ip_info (
    ip      TEXT PRIMARY KEY,
    asn     INTEGER,
    as_name TEXT,
    cc      TEXT,
    rdns    TEXT,
    kind    TEXT NOT NULL,   -- scanner | hosting | isp
    reason  TEXT,            -- why it counts as a scanner
    updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ip_info_kind ON ip_info(kind);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def connect(readonly=False):
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout=10000")
    if readonly:
        conn.execute("PRAGMA query_only=1")
    else:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA)
    return conn


class Writer(threading.Thread):
    """Batches inserts on a background thread so capture never waits on disk."""

    def __init__(self, table, columns):
        super().__init__(daemon=True, name=f"writer-{table}")
        self.columns = columns
        self.sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})"
        self.q = queue.Queue(maxsize=100_000)
        self.dropped = 0

    def put(self, **row):
        try:
            self.q.put_nowait(tuple(row.get(c) for c in self.columns))
        except queue.Full:
            self.dropped += 1

    def run(self):
        conn = connect()
        while True:
            rows = [self.q.get()]
            deadline = time.monotonic() + 1.0
            while len(rows) < 5000:
                try:
                    rows.append(self.q.get(timeout=max(0, deadline - time.monotonic())))
                except queue.Empty:
                    break
            try:
                with conn:
                    conn.executemany(self.sql, rows)
            except sqlite3.Error as e:
                log(f"db write failed, {len(rows)} rows lost: {e}")


def escape_bytes(data, limit=256):
    """Printable ASCII kept, everything else as \\xNN, for showing raw client bytes safely."""
    out = []
    for b in data[:limit]:
        if b in (0x0a, 0x0d):
            out.append({0x0a: "\\n", 0x0d: "\\r"}[b])
        elif 0x20 <= b < 0x7f and b != 0x5c:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    if len(data) > limit:
        out.append(f"... (+{len(data) - limit} bytes)")
    return "".join(out)


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}


def dns_query(payload):
    """(qname, qtype) if the payload is a DNS query, else None."""
    if len(payload) < 17 or payload[2] & 0x80 or struct.unpack_from("!H", payload, 4)[0] < 1:
        return None
    i, labels = 12, []
    while True:
        if i >= len(payload):
            return None
        n = payload[i]
        if n == 0:
            break
        if n & 0xC0 or i + 1 + n > len(payload):
            return None
        labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    qtype = struct.unpack_from("!H", payload, i + 1)[0] if i + 3 <= len(payload) else 0
    return ".".join(labels).lower() or ".", DNS_TYPES.get(qtype, str(qtype))
