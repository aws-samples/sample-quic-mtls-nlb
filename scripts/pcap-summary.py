#!/usr/bin/env python3
"""Bidirectional summary of a QUIC pcap: packet counts + bytes by direction,
long-header type breakdown, and short-header (1-RTT / data phase) count.
This is the actual proof that packets *transferred* — not just that the
long-header packets had the right DCID layout.

Usage: pcap-summary.py <pcap> [server_pod_ip]
"""
import struct
import sys
from collections import Counter

LONG_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}


def read_pcap(fp):
    magic = fp.read(4)
    if magic not in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        raise RuntimeError(f"bad pcap magic: {magic!r}")
    e = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"
    fp.read(20)
    while True:
        rec = fp.read(16)
        if len(rec) < 16:
            return
        _s, _u, incl, _o = struct.unpack(e + "IIII", rec)
        data = fp.read(incl)
        if len(data) < incl:
            return
        yield data


def parse_sll2(pkt):
    # Linux "cooked v2" link-layer header is 20 bytes; proto @ offset 0..2
    proto = struct.unpack(">H", pkt[0:2])[0]
    if proto == 0x0800:
        return pkt[20:]
    if proto == 0x86DD:
        return pkt[20:]
    return None


def parse_ipv4(pkt):
    if len(pkt) < 20:
        return None, None, None, None
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    if proto != 17:  # UDP
        return None, None, None, None
    return pkt[ihl:], src, dst, ihl


def parse_udp(pkt):
    if len(pkt) < 8:
        return None, None, None
    sport, dport, length = struct.unpack(">HHH", pkt[0:6])
    return pkt[8:], sport, dport


def quic_header_summary(payload):
    if not payload:
        return "empty", 0
    b0 = payload[0]
    long = (b0 & 0x80) != 0
    fixed = (b0 & 0x40) != 0
    if not fixed:
        return "not-quic", 0
    if not long:
        # short-header (1-RTT): dcid length is implicit, not on the wire
        return "1-RTT", 0
    if len(payload) < 6:
        return "long-truncated", 0
    dcid_len = payload[5]
    long_type = (b0 & 0x30) >> 4
    typename = LONG_TYPES.get(long_type, "?")
    version = struct.unpack(">I", payload[1:5])[0]
    if version == 0:
        typename = "VersionNegotiation"
    return typename, dcid_len


def main(path, server_ip=None):
    counts = Counter()
    bytes_by_dir = Counter()
    pkts_by_dir = Counter()
    total = 0

    with open(path, "rb") as fp:
        for raw in read_pcap(fp):
            ip_pkt = parse_sll2(raw)
            if ip_pkt is None:
                continue
            udp_hdr, src, dst, _ = parse_ipv4(ip_pkt)
            if udp_hdr is None:
                continue
            udp_payload, sport, dport = parse_udp(udp_hdr)
            if udp_payload is None:
                continue

            # Direction is heuristic: if server_ip is provided, use it;
            # otherwise infer from the port with the smaller value being the
            # server (port 3000 on target, ephemeral on client).
            if server_ip:
                direction = "S->C" if src == server_ip else "C->S"
            else:
                direction = "S->C" if sport < dport else "C->S"

            typ, dcid_len = quic_header_summary(udp_payload)
            counts[(typ, direction)] += 1
            bytes_by_dir[direction] += len(udp_payload)
            pkts_by_dir[direction] += 1
            total += 1

    print(f"total datagrams: {total}")
    print(f"packets client->server: {pkts_by_dir.get('C->S', 0)}")
    print(f"packets server->client: {pkts_by_dir.get('S->C', 0)}")
    print(f"bytes  client->server: {bytes_by_dir.get('C->S', 0)}")
    print(f"bytes  server->client: {bytes_by_dir.get('S->C', 0)}")
    print()
    print("packet type × direction:")
    for (typ, d), n in sorted(counts.items()):
        print(f"  {typ:<20s} {d:>5s}  {n:>4d}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
