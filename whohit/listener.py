"""Catch-all TCP listener: works out what each client was after.

nftables redirects every inbound TCP port except SSH to this one socket. For
each connection the original port is recovered with SO_ORIGINAL_DST, then
whatever the client sends is read and logged:

  HTTP   Host header, method, path, User-Agent and headers. Credentials
         (auth/cookie/API-key headers, token-like query parameters) are
         recorded as present, but their values are never stored.
  TLS    SNI and ALPN from the ClientHello. The handshake is then completed
         with a self-signed certificate: a client that refuses it validates
         certificates (browser, app, SDK), and one that accepts it gets its
         HTTP request logged like plain HTTP.
  SMTP   (25/587/2525) greet, play along until RCPT TO, record the envelope,
         then refuse with a temporary error. No message is ever accepted.
  other  a protocol guess from the first bytes, plus an escaped preview.

sessions.flags holds the "is something real still using this?" signals:
  credentials    the client sent credentials (header or query parameter)
  login-submit   a request body had password-like fields, e.g. a login form being
                 submitted. Only field names are stored, never values.
  cert-rejected  a TLS client aborted on our certificate, so it checks certs
  mail           a server tried to deliver mail
  smtp-auth      a mail client tried to log in to send mail
"""
import collections
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import warnings

from common import Writer, dns_query, escape_bytes, log

PORT = int(os.environ.get("WHOHIT_LISTEN_PORT", "9999"))
CERT, KEY = "/etc/whohit/tls.crt", "/etc/whohit/tls.key"
MAX_CONNS, MAX_PER_IP = 512, 48
TIMEOUT = 10        # seconds a client gets to say something (per phase)
SMTP_TIMEOUT = 30
SO_ORIGINAL_DST = 80

HTTP_METHODS = {b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH",
                b"CONNECT", b"TRACE", b"PROPFIND", b"PRI"}
CREDENTIAL_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key",
                      "api-key", "x-auth-token", "x-access-token"}
CREDENTIAL_QUERY = re.compile(
    r"(?i)([?&][^=&#]*(?:token|key|secret|pass|auth|sig|session|code)[^=&#]*=)[^&#]*")
CERT_REJECTED = {"TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_CERTIFICATE_UNKNOWN",
                 "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
                 "TLSV1_ALERT_ACCESS_DENIED"}
# Request-body field names that mean a secret is being submitted.
SECRET_FIELD = re.compile(r"(?i)pass|pwd|secret|token|otp|mfa|2fa|cvv|card|\bpin\b|\bcode\b")
MAX_BODY = 65536
# Login commands in text protocols (IMAP LOGIN, POP3/FTP PASS, AUTH ...).
SECRET_ARGS = re.compile(rb"(?im)^(\S*[ \t]*(?:PASS|LOGIN|AUTH(?:ENTICATE)?)[ \t]+)[^\r\n]*")

SMTP_PORTS = {25, 587, 2525}
# Protocols where the server speaks first; without a greeting the client stays silent.
GREETINGS = {21: (b"220 FTP server ready\r\n", "ftp"),
             110: (b"+OK POP3 server ready\r\n", "pop3"),
             143: (b"* OK IMAP4rev1 server ready\r\n", "imap")}

NOT_FOUND = (b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
             b"Content-Length: 10\r\nConnection: close\r\n\r\nNot Found\n")

writer = Writer("sessions", ["ts", "src_ip", "src_port", "dst_port", "app", "domain", "method",
                             "path", "user_agent", "flags", "detail", "preview"])


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(["http/1.1"])
    try:  # let old clients through too: we want their request, not their security
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


TLS = tls_context()


def original_port(sock):
    try:
        return struct.unpack_from("!H", sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16), 2)[0]
    except OSError:
        return sock.getsockname()[1]


def peek(sock, want, deadline):
    """Up to `want` bytes the client has sent, without consuming them."""
    data = b""
    while len(data) < want:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            more = sock.recv(want, socket.MSG_PEEK)
        except OSError:
            break
        if not more:
            break
        if len(more) == len(data):
            time.sleep(0.05)  # MSG_PEEK returns what is buffered right away; wait for more
        data = more
    return data


def read_until(sock, marker, limit, deadline):
    """Consume bytes until `marker` (None: until EOF), `limit` bytes or the deadline."""
    data = b""
    while len(data) < limit and (marker is None or marker not in data):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            chunk = sock.recv(min(4096, limit - len(data)))
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def normalize_host(host):
    if not host:
        return None
    host = host.strip().lower()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".")[:253] or None


def read_request(sock, deadline):
    """Request head plus up to MAX_BODY bytes of body, as announced by Content-Length."""
    raw = read_until(sock, b"\r\n\r\n", 16384, deadline)
    head, sep, body = raw.partition(b"\r\n\r\n")
    m = re.search(rb"(?im)^content-length:[ \t]*(\d+)", head)
    want = min(int(m.group(1)), MAX_BODY) if m and sep else 0
    if len(body) < want:
        body += read_until(sock, None, want - len(body), deadline)
    return head + sep + body[:want]


def describe_body(ctype, body, flags):
    """Size, type and field names of a request body. Values are never kept."""
    shape = {"bytes": len(body), "type": ctype.split(";")[0].strip()[:60]}
    fields = []
    text = body.decode("utf-8", "replace")
    if "json" in ctype:
        try:
            obj = json.loads(text)
            obj = obj[0] if isinstance(obj, list) and obj else obj
            fields = list(obj) if isinstance(obj, dict) else []
        except ValueError:
            pass
    elif "x-www-form-urlencoded" in ctype:
        fields = [urllib.parse.unquote_plus(p.partition("=")[0]) for p in text.split("&") if p]
    elif "multipart/form-data" in ctype:
        fields = re.findall(r'name="([^"]{1,80})"', text)
    if fields:
        shape["fields"] = [str(f)[:60] for f in fields[:50]]
        if any(SECRET_FIELD.search(f) for f in shape["fields"]):
            flags.add("login-submit")
    return shape


def parse_http(raw, row, flags, detail):
    head, _, body = raw.partition(b"\r\n\r\n")
    head = head.decode("latin-1")
    request_line, *header_lines = head.split("\r\n")
    parts = request_line.split(" ")
    headers = {}
    for line in header_lines[:100]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name, value = name.strip().lower(), value.strip()
        if name in CREDENTIAL_HEADERS:
            value = f"[redacted, {len(value)} chars]"
            flags.add("credentials")
        headers[name] = value[:1024]
    path = parts[1] if len(parts) > 1 else ""
    redacted = CREDENTIAL_QUERY.sub(r"\1[redacted]", path)
    if redacted != path:
        flags.add("credentials")
    row.update(method=parts[0][:16], path=redacted[:2048], domain=normalize_host(headers.get("host")),
               user_agent=headers.get("user-agent", "")[:512] or None)
    detail["headers"] = headers
    if len(parts) > 2:
        detail["version"] = parts[2][:16]
    if body:
        detail["body"] = describe_body(headers.get("content-type", ""), body, flags)


def parse_client_hello(rec):
    """SNI, ALPN and offered TLS versions from a ClientHello record (best effort)."""
    out = {}
    try:
        if rec[0] != 0x16 or rec[5] != 0x01:
            return out
        p = 9 + 2 + 32                                # headers, client_version, random
        p += 1 + rec[p]                               # session id
        p += 2 + int.from_bytes(rec[p:p + 2], "big")  # cipher suites
        p += 1 + rec[p]                               # compression methods
        end = min(p + 2 + int.from_bytes(rec[p:p + 2], "big"), len(rec))
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack_from("!HH", rec, p)
            body = rec[p + 4:p + 4 + elen]
            if etype == 0 and len(body) >= 5 and body[2] == 0:
                out["sni"] = body[5:5 + int.from_bytes(body[3:5], "big")].decode("ascii", "replace")
            elif etype == 16:
                q, protos = 2, []
                while q < len(body):
                    protos.append(body[q + 1:q + 1 + body[q]].decode("ascii", "replace"))
                    q += 1 + body[q]
                out["alpn"] = protos
            elif etype == 43 and body:
                names = {0x0304: "1.3", 0x0303: "1.2", 0x0302: "1.1", 0x0301: "1.0"}
                out["versions"] = [names[v] for v in struct.unpack_from(f"!{body[0] // 2}H", body, 1)
                                   if v in names]
            p += 4 + elen
    except (IndexError, struct.error):
        pass
    return out


def guess_app(data, port):
    if data.startswith(b"SSH-"):
        return "ssh"
    if data.startswith(b"RFB "):
        return "vnc"
    if len(data) > 4 and data[0] == 3 and data[1] == 0:
        return "rdp"
    if data[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "smb"
    if data[4:8] in (b"\x04\xd2\x16\x2f", b"\x00\x03\x00\x00"):
        return "postgres"
    if data[:1] == b"\xff" and data[1:2] in (b"\xfb", b"\xfc", b"\xfd", b"\xfe"):
        return "telnet"
    if data[:1] == b"*" and b"\r\n$" in data[:16]:
        return "redis"
    if data.startswith(b"JDWP-Handshake"):
        return "jdwp"
    if data[:1] == b"\x10" and port in (1883, 8883):
        return "mqtt"
    if port in GREETINGS:
        return GREETINGS[port][1]
    return "unknown"


def handle_tls(sock, row, flags, detail):
    deadline = time.monotonic() + TIMEOUT
    header = peek(sock, 5, deadline)
    want = 5 + (struct.unpack_from("!H", header, 3)[0] if len(header) == 5 else 0)
    info = parse_client_hello(peek(sock, min(want, 16389), deadline))
    row.update(app="tls", domain=normalize_host(info.get("sni")))
    detail.update(info)
    sock.settimeout(TIMEOUT)
    try:
        tsock = TLS.wrap_socket(sock, server_side=True)
    except (ssl.SSLError, OSError) as e:
        reason = getattr(e, "reason", None)
        detail["handshake"] = f"failed: {reason or e}"[:200]
        if reason in CERT_REJECTED:
            flags.add("cert-rejected")
        return
    with tsock:
        detail["handshake"] = f"completed ({tsock.version()})"
        raw = read_request(tsock, time.monotonic() + TIMEOUT)
        if raw.split(b" ", 1)[0] in HTTP_METHODS:
            parse_http(raw, row, flags, detail)
            row["domain"] = row["domain"] or normalize_host(info.get("sni"))
            row["app"] = "https"
            tsock.sendall(NOT_FOUND)
        elif raw:
            row["preview"] = escape_bytes(SECRET_ARGS.sub(rb"\1[redacted]", raw))


def smtp_dialogue(readline, send, envelope, flags):
    envelope["lines"] = 0
    while envelope["lines"] < 50 and (line := readline()) is not None:
        envelope["lines"] += 1
        cmd = line.upper()
        if cmd.startswith(("EHLO", "HELO")):
            envelope["helo"] = line[5:].strip()[:200]
            send("250 localhost")
        elif cmd.startswith("MAIL FROM:"):
            envelope["mail_from"] = line[10:].strip()[:320]
            flags.add("mail")
            send("250 2.1.0 OK")
        elif cmd.startswith("RCPT TO:"):
            if len(envelope["rcpt"]) < 20:
                envelope["rcpt"].append(line[8:].strip()[:320])
            send("450 4.2.1 Mailbox temporarily unavailable")
        elif cmd.startswith("AUTH"):
            envelope["auth_mechanism"] = (line.split()[1:2] or [""])[0][:20]  # never the credential
            flags.add("smtp-auth")
            send("535 5.7.8 Authentication failed")
        elif cmd.startswith("STARTTLS"):
            send("454 4.7.0 TLS not available")
        elif cmd.startswith("DATA"):
            send("554 5.5.1 No valid recipients")
        elif cmd.startswith("QUIT"):
            send("221 2.0.0 Bye")
            break
        elif cmd.startswith(("RSET", "NOOP")):
            send("250 2.0.0 OK")
        else:
            envelope.setdefault("other", []).append(escape_bytes(line.encode("latin-1"), 80))
            send("502 5.5.2 Command not recognised")


def handle_smtp(sock, row, flags, detail):
    deadline = time.monotonic() + SMTP_TIMEOUT
    buf = b""
    envelope = {"rcpt": []}

    def send(line):
        sock.sendall(line.encode() + b"\r\n")

    def readline():
        nonlocal buf
        while b"\n" not in buf:
            more = read_until(sock, b"\n", 4096 - len(buf), deadline) if len(buf) < 4096 else b""
            if not more:
                return None
            buf += more
        line, _, buf = buf.partition(b"\n")
        return line.rstrip(b"\r").decode("latin-1")

    try:
        send("220 localhost ESMTP")
        smtp_dialogue(readline, send, envelope, flags)
    except OSError as e:
        detail["error"] = str(e)[:200]
    lines = envelope.pop("lines", 0)
    row["app"] = "smtp" if lines else "silent"
    if envelope["rcpt"]:
        m = re.search(r"@([^>\s]+)", envelope["rcpt"][0])
        row["domain"] = normalize_host(m.group(1)) if m else None
    if lines:
        detail["smtp"] = envelope


def handle(sock, addr):
    dst_port = original_port(sock)
    row = {"ts": time.time(), "src_ip": addr[0], "src_port": addr[1], "dst_port": dst_port}
    flags, detail = set(), {}
    try:
        if dst_port in SMTP_PORTS:
            handle_smtp(sock, row, flags, detail)
            return
        if dst_port in GREETINGS:
            sock.sendall(GREETINGS[dst_port][0])
        deadline = time.monotonic() + TIMEOUT
        if not peek(sock, 1, deadline):
            row["app"] = "silent"
            return
        head = peek(sock, 8, min(deadline, time.monotonic() + 1))
        if head[:2] == b"\x16\x03":
            handle_tls(sock, row, flags, detail)
        elif head.split(b" ", 1)[0] in HTTP_METHODS:
            parse_http(read_request(sock, deadline), row, flags, detail)
            row["app"] = "http"
            sock.sendall(NOT_FOUND)
        else:
            data = read_until(sock, None, 4096, min(deadline, time.monotonic() + 1))
            row["app"] = guess_app(data, dst_port)
            if dst_port == 53 and (q := dns_query(data[2:])):
                row.update(app="dns", domain=q[0], method=q[1])
            row["preview"] = escape_bytes(SECRET_ARGS.sub(rb"\1[redacted]", data))
    except OSError as e:
        detail["error"] = str(e)[:200]
    finally:
        sock.close()
        row.setdefault("app", "error")
        row["flags"] = " ".join(sorted(flags)) or None
        row["detail"] = json.dumps(detail) if detail else None
        writer.put(**row)


def main():
    writer.start()
    server = socket.create_server(("0.0.0.0", PORT), backlog=1024)
    slots = threading.BoundedSemaphore(MAX_CONNS)
    per_ip = collections.Counter()
    lock = threading.Lock()
    log(f"listening on :{PORT}")

    def release_ip(ip):
        with lock:
            per_ip[ip] -= 1
            if per_ip[ip] <= 0:
                del per_ip[ip]

    def serve(sock, addr):
        try:
            handle(sock, addr)
        finally:
            slots.release()
            release_ip(addr[0])

    while True:
        sock, addr = server.accept()
        with lock:
            over = per_ip[addr[0]] >= MAX_PER_IP
            if not over:
                per_ip[addr[0]] += 1
        if not over and slots.acquire(blocking=False):
            threading.Thread(target=serve, args=(sock, addr), daemon=True).start()
            continue
        if not over:
            release_ip(addr[0])
        writer.put(ts=time.time(), src_ip=addr[0], src_port=addr[1], dst_port=original_port(sock), app="busy")
        sock.close()


if __name__ == "__main__":
    main()
