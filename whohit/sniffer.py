"""Passively log every inbound connection attempt on the public interface.

One row per TCP SYN, per UDP flow (deduplicated per minute) and per ICMP echo
request. Frames come off an AF_PACKET socket, which sees the original
destination port before the listener's nftables redirect rewrites it, so this
is the source of truth for "which ports are people trying to reach".
"""
import ctypes
import os
import socket
import struct
import subprocess
import time

from common import Writer, dns_query, escape_bytes, log

IFACE = os.environ.get("WHOHIT_IFACE", "eth0")
# Inbound-relevant packets only: bare SYNs, UDP, ping requests. Outbound UDP
# also passes so replies to our own queries can be recognised and skipped.
BPF_FILTER = "(tcp and tcp[13] & 0x12 == 2) or udp or (icmp and icmp[0] == 8)"

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
SO_ATTACH_FILTER = 26
PACKET_HOST = 0
PACKET_OUTGOING = 4

# How long a repeat of the same attempt is folded into the first one.
DEDUP_SECONDS = {"tcp": 30, "udp": 60, "icmp": 60}
OUTBOUND_UDP_SECONDS = 120


def attach_bpf(sock):
    """Have the kernel drop everything uninteresting before Python sees it."""
    out = subprocess.run(["tcpdump", "-y", "EN10MB", "-ddd", BPF_FILTER],
                         capture_output=True, text=True, check=True).stdout.split()
    count, insns = int(out[0]), [int(x) for x in out[1:]]
    prog = b"".join(struct.pack("HBBI", *insns[i:i + 4]) for i in range(0, 4 * count, 4))
    buf = ctypes.create_string_buffer(prog, len(prog))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack("HL", count, ctypes.addressof(buf)))


def describe_udp(dport, payload):
    if len(payload) >= 5 and payload[0] & 0xC0 == 0xC0 and payload[1:5] != b"\0\0\0\0":
        return f"QUIC long header, version 0x{payload[1:5].hex()}"
    return escape_bytes(payload, 64) if payload else "(empty)"


def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        attach_bpf(sock)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        log(f"kernel filter not attached, filtering in Python only: {e}")
    sock.bind((IFACE, 0))
    writer = Writer("attempts", ["ts", "src_ip", "src_port", "dst_port", "proto", "domain", "info"])
    writer.start()
    log(f"sniffing on {IFACE}")

    recent = {}        # dedup key -> last time seen
    outbound_udp = {}  # (remote ip, remote port, local port) -> last time we sent to it
    next_prune = time.monotonic() + 60

    while True:
        frame, addr = sock.recvfrom(65535)
        now = time.monotonic()
        if now > next_prune:
            recent = {k: t for k, t in recent.items() if now - t < 120}
            outbound_udp = {k: t for k, t in outbound_udp.items() if now - t < OUTBOUND_UDP_SECONDS}
            next_prune = now + 60

        pkttype = addr[2]
        if len(frame) < 34 or struct.unpack_from("!H", frame, 12)[0] != ETH_P_IP:
            continue
        ihl = (frame[14] & 0x0F) * 4
        if struct.unpack_from("!H", frame, 20)[0] & 0x1FFF:  # not the first fragment
            continue
        proto_num, l4 = frame[23], 14 + ihl
        src, dst = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])

        if pkttype == PACKET_OUTGOING:
            if proto_num == 17 and len(frame) >= l4 + 4:
                sport, dport = struct.unpack_from("!HH", frame, l4)
                outbound_udp[(dst, dport, sport)] = now
            continue
        if pkttype != PACKET_HOST:
            continue

        row = {"src_ip": src}
        if proto_num == 6 and len(frame) >= l4 + 14:
            if frame[l4 + 13] & 0x12 != 0x02:
                continue
            sport, dport = struct.unpack_from("!HH", frame, l4)
            key = ("tcp", src, sport, dport)
            row.update(proto="tcp", src_port=sport, dst_port=dport)
        elif proto_num == 17 and len(frame) >= l4 + 8:
            sport, dport = struct.unpack_from("!HH", frame, l4)
            if (src, sport, dport) in outbound_udp:
                continue  # a reply to something we sent
            payload = frame[l4 + 8:]
            q = dns_query(payload)
            row.update(proto="udp", src_port=sport, dst_port=dport)
            if q:
                row.update(domain=q[0], info=f"DNS {q[1]} query")
            else:
                row["info"] = describe_udp(dport, payload)
            key = ("udp", src, dport, row.get("domain"))
        elif proto_num == 1 and len(frame) > l4 and frame[l4] == 8:
            key = ("icmp", src)
            row.update(proto="icmp", info="echo request")
        else:
            continue

        # Fixed window from the first logged packet, so a steady stream still
        # shows up once per window instead of being suppressed forever.
        if now - recent.get(key, -1e9) < DEDUP_SECONDS[row["proto"]]:
            continue
        recent[key] = now
        writer.put(ts=time.time(), **row)


if __name__ == "__main__":
    main()
