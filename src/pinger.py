#!/usr/bin/env python3
"""Packet-level ICMP pinger with RTT statistics and a traceroute mode.

Builds ICMP echo-request packets byte-by-byte (type, code, checksum,
identifier, sequence number, payload) and sends them over a raw socket.
Standard library only.

Usage:
    python3 pinger.py HOST [-c COUNT] [-t TIMEOUT] [-i INTERVAL]
    python3 pinger.py HOST --traceroute [--max-hops N]

Examples:
    python3 pinger.py 127.0.0.1 -c 5
    python3 pinger.py 1.1.1.1 --traceroute

Raw sockets require elevated privileges on most systems (root, or
CAP_NET_RAW on Linux / administrator on Windows).
"""

import argparse
import os
import socket
import statistics
import struct
import sys
import time

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071): 16-bit one's complement of the
    one's complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo_request(identifier: int, sequence: int, payload_size: int = 56) -> bytes:
    """Assemble an ICMP echo-request packet with an embedded send timestamp."""
    payload = struct.pack("!d", time.time()) + b"Q" * max(0, payload_size - 8)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    cksum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cksum, identifier, sequence)
    return header + payload


def parse_icmp(packet: bytes):
    """Return (type, identifier, sequence, embedded_timestamp) from an
    IP packet containing an ICMP message, or None if not parseable."""
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    icmp = packet[ihl:]
    if len(icmp) < 16:
        return None
    icmp_type, _code, _ck, identifier, sequence = struct.unpack("!BBHHH", icmp[:8])
    sent_at = None
    if icmp_type in (ICMP_ECHO_REPLY,) and len(icmp) >= 16:
        (sent_at,) = struct.unpack("!d", icmp[8:16])
    if icmp_type == ICMP_TIME_EXCEEDED and len(icmp) >= ihl + 8 + 16:
        # Original IP header + first 8 bytes of the original ICMP packet.
        inner = icmp[8:]
        inner_ihl = (inner[0] & 0x0F) * 4
        inner_icmp = inner[inner_ihl:inner_ihl + 8]
        if len(inner_icmp) == 8:
            _t, _c, _k, identifier, sequence = struct.unpack("!BBHHH", inner_icmp)
    return icmp_type, identifier, sequence, sent_at


def ping_once(sock: socket.socket, dest: str, identifier: int, sequence: int,
              timeout: float, ttl: int = 64):
    """Send one echo request; return (kind, responder_ip, rtt_ms).
    kind is 'reply' or 'exceeded'; returns None on timeout."""
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    sock.settimeout(timeout)
    packet = build_echo_request(identifier, sequence)
    start = time.time()
    sock.sendto(packet, (dest, 0))
    deadline = start + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            return None
        parsed = parse_icmp(data)
        if parsed is None:
            continue
        icmp_type, pkt_id, pkt_seq, _sent = parsed
        if pkt_id != identifier or pkt_seq != sequence:
            continue
        rtt_ms = (time.time() - start) * 1000.0
        if icmp_type == ICMP_ECHO_REPLY:
            return ("reply", addr[0], rtt_ms)
        if icmp_type == ICMP_TIME_EXCEEDED:
            return ("exceeded", addr[0], rtt_ms)
    return None


def do_ping(host: str, count: int, timeout: float, interval: float) -> int:
    dest = socket.gethostbyname(host)
    identifier = os.getpid() & 0xFFFF
    print(f"PING {host} ({dest}): {56} data bytes")
    rtts = []
    transmitted = 0
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        for seq in range(1, count + 1):
            transmitted += 1
            result = ping_once(sock, dest, identifier, seq, timeout)
            if result is None:
                print(f"Request timeout for icmp_seq {seq}")
            else:
                _kind, responder, rtt = result
                rtts.append(rtt)
                print(f"Reply from {responder}: icmp_seq={seq} time={rtt:.2f} ms")
            if seq < count:
                time.sleep(interval)
    received = len(rtts)
    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    print(f"\n--- {host} ping statistics ---")
    print(f"{transmitted} packets transmitted, {received} received, {loss:.1f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max/stddev = {min(rtts):.2f}/{statistics.mean(rtts):.2f}/"
              f"{max(rtts):.2f}/{statistics.pstdev(rtts) if len(rtts) > 1 else 0.0:.2f} ms")
    return 0 if received else 1


def do_udp_ping(host: str, port: int, count: int, timeout: float, interval: float) -> int:
    """Unprivileged fallback: timestamped UDP echo probes against a UDP
    echo server (see --serve). Same RTT/loss statistics as ICMP mode."""
    dest = socket.gethostbyname(host)
    print(f"UDP PING {host} ({dest}): port {port}")
    rtts = []
    transmitted = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for seq in range(1, count + 1):
            transmitted += 1
            start = time.time()
            sock.sendto(struct.pack("!Id", seq, start), (dest, port))
            try:
                data, _addr = sock.recvfrom(2048)
                rtt = (time.time() - start) * 1000.0
                rtts.append(rtt)
                print(f"Reply from {dest}: udp_seq={seq} time={rtt:.2f} ms")
            except socket.timeout:
                print(f"Request timeout for udp_seq {seq}")
            if seq < count:
                time.sleep(interval)
    received = len(rtts)
    loss = 100.0 * (transmitted - received) / transmitted if transmitted else 0.0
    print(f"\n--- {host} udp ping statistics ---")
    print(f"{transmitted} packets transmitted, {received} received, {loss:.1f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max/stddev = {min(rtts):.2f}/{statistics.mean(rtts):.2f}/"
              f"{max(rtts):.2f}/{statistics.pstdev(rtts) if len(rtts) > 1 else 0.0:.2f} ms")
    return 0 if received else 1


def serve_udp(port: int) -> int:
    """Tiny UDP echo server used by --udp mode (for unprivileged testing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", port))
        print(f"UDP echo server listening on port {port} (Ctrl+C to stop)")
        while True:
            data, addr = sock.recvfrom(2048)
            sock.sendto(data, addr)


def do_traceroute(host: str, max_hops: int, timeout: float) -> int:
    dest = socket.gethostbyname(host)
    identifier = os.getpid() & 0xFFFF
    print(f"traceroute to {host} ({dest}), {max_hops} hops max")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        for ttl in range(1, max_hops + 1):
            result = ping_once(sock, dest, identifier, ttl, timeout, ttl=ttl)
            if result is None:
                print(f"{ttl:2d}  *")
                continue
            kind, responder, rtt = result
            try:
                name = socket.gethostbyaddr(responder)[0]
            except socket.herror:
                name = responder
            print(f"{ttl:2d}  {name} ({responder})  {rtt:.2f} ms")
            if kind == "reply":
                break
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Packet-level ICMP pinger")
    parser.add_argument("host", nargs="?", help="hostname or IP address")
    parser.add_argument("-c", "--count", type=int, default=4)
    parser.add_argument("-t", "--timeout", type=float, default=2.0)
    parser.add_argument("-i", "--interval", type=float, default=1.0)
    parser.add_argument("--traceroute", action="store_true")
    parser.add_argument("--max-hops", type=int, default=30)
    parser.add_argument("--udp", action="store_true",
                        help="use UDP echo probes instead of ICMP (no privileges needed)")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--serve", action="store_true",
                        help="run the UDP echo server used by --udp mode")
    args = parser.parse_args(argv)
    if args.serve:
        return serve_udp(args.port)
    if not args.host:
        parser.error("host is required unless --serve is given")
    try:
        if args.traceroute:
            return do_traceroute(args.host, args.max_hops, args.timeout)
        if args.udp:
            return do_udp_ping(args.host, args.port, args.count, args.timeout, args.interval)
        return do_ping(args.host, args.count, args.timeout, args.interval)
    except PermissionError:
        print("error: raw sockets need elevated privileges "
              "(run with sudo, or grant CAP_NET_RAW)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
