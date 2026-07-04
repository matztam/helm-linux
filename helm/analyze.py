"""Decode a captured Helm session from a pcap.

Reassembles TCP streams on the Helm control port and prints the
[u16 type][u16 0xBEEF][u32 len][payload] frames (see helm_client.parse_frames).
Handy for extending the protocol on other units (e.g. capturing key messages).

    python3 -m helm.analyze helm.pcap --port 51200
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter

from .helm_client import parse_frames

# Names for known message types (see PROTOCOL.md).
TYPES = {
    0x083F: "hello", 0x0AA9: "token", 0x1644: "acquire", 0x1645: "context",
    0x1648: "subscribe", 0x1649: "event", 0x164C: "touch",
}


def _read_pcap_tcp(path: str, port: int | None):
    """Yield (src, sport, dst, dport, payload) for TCP segments in a classic pcap."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise ValueError("only classic pcap is supported (convert with "
                         "`tshark -F pcap` or capture with `tcpdump`)")
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        base = 14 if linktype == 1 else (16 if linktype == 113 else 0)
        if linktype == 1 and pkt[12:14] != b"\x08\x00":
            continue
        ip = pkt[base:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0xF) * 4
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack(">HH", tcp[0:4])
        payload = tcp[(tcp[12] >> 4) * 4:]
        if port and port not in (sport, dport):
            continue
        if payload:
            yield src, sport, dst, dport, payload


def analyze(path: str, port: int | None = None) -> int:
    streams: dict[tuple, bytearray] = {}
    for src, sp, dst, dp, payload in _read_pcap_tcp(path, port):
        streams.setdefault((src, sp, dst, dp), bytearray()).extend(payload)
    if not streams:
        print("No TCP payload found (check --port).")
        return 1
    for (src, sp, dst, dp), buf in sorted(streams.items(), key=lambda kv: -len(kv[1])):
        frames = list(parse_frames(bytes(buf)))
        if not frames:
            continue
        print(f"\n=== {src}:{sp} -> {dst}:{dp}  ({len(buf)} bytes, "
              f"{len(frames)} frames) ===")
        hist = Counter(t for t, _ in frames)
        print("  types: " + ", ".join(f"0x{t:04x}({TYPES.get(t,'?')})×{c}"
                                       for t, c in hist.most_common()))
        for typ, pl in frames[:40]:
            ap = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:48])
            print(f"    0x{typ:04x} {TYPES.get(typ,'?'):9} len={len(pl):<6} "
                  f"{pl[:40].hex()}  {ap}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Decode a Helm session pcap")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=51200, help="control port (default 51200)")
    args = ap.parse_args(argv)
    return analyze(args.pcap, args.port)


if __name__ == "__main__":
    sys.exit(main())
