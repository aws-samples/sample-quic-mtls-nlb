#!/usr/bin/env python3
"""Parse a pcap of UDP:3000 QUIC traffic and print DCID length + hex for every
QUIC Long Header packet. This is the raw wire-level evidence for the blog's
Validation section (\"the DCID in Handshake and 0-RTT packets is 17 bytes with
the Server ID at offset bytes 1-8\").
"""
import struct
import sys

LONG_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}

def read_pcap_records(fp):
    magic = fp.read(4)
    if magic not in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        raise RuntimeError(f"bad pcap magic: {magic!r}")
    endian = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"
    # skip rest of global header
    fp.read(20)
    while True:
        rec = fp.read(16)
        if len(rec) < 16:
            return
        _sec, _usec, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
        data = fp.read(incl_len)
        if len(data) < incl_len:
            return
        yield data


def parse_linux_sll2(data):
    # SLL2: 20-byte header; protocol at offset 0..2 (big-endian)
    proto = struct.unpack(">H", data[0:2])[0]
    if proto == 0x0800:  # IPv4
        return data[20:]
    if proto == 0x86DD:  # IPv6
        return data[20:]
    return None


def parse_ipv4(pkt):
    ihl = (pkt[0] & 0x0F) * 4
    proto = pkt[9]
    if proto != 17:  # UDP
        return None
    return pkt[ihl:]


def parse_udp(pkt):
    if len(pkt) < 8:
        return None
    return pkt[8:]  # skip UDP header


def inspect_quic(payload, idx):
    if not payload:
        return
    b0 = payload[0]
    is_long = (b0 & 0x80) != 0
    fixed = (b0 & 0x40) != 0
    if not (is_long and fixed):
        return  # short header or not QUIC
    if len(payload) < 6:
        return
    version = struct.unpack(">I", payload[1:5])[0]
    dcid_len = payload[5]
    if len(payload) < 6 + dcid_len:
        return
    dcid = payload[6:6 + dcid_len]
    long_type = (b0 & 0x30) >> 4
    typename = LONG_TYPES.get(long_type, "?")
    if version == 0:
        typename = "VersionNegotiation"
    print(f"pkt#{idx:03d} type={typename:12s} version=0x{version:08x} "
          f"dcid_len={dcid_len:2d}  dcid={dcid.hex()}")


def main(path):
    counts = {}
    with open(path, "rb") as fp:
        for i, raw in enumerate(read_pcap_records(fp), 1):
            # Linux "cooked v2" link-layer
            ip_pkt = parse_linux_sll2(raw)
            if ip_pkt is None:
                continue
            udp_payload = parse_udp(parse_ipv4(ip_pkt) or b"")
            if not udp_payload:
                continue
            # Inspect the leading QUIC packet in the datagram. Coalesced packets
            # exist, but the first packet is enough for the blog's claim.
            if not udp_payload or (udp_payload[0] & 0xC0) != 0xC0:
                continue
            inspect_quic(udp_payload, i)
            dl = udp_payload[5] if len(udp_payload) > 5 else 0
            counts[dl] = counts.get(dl, 0) + 1
    print()
    print("DCID length histogram:", counts)


if __name__ == "__main__":
    main(sys.argv[1])
