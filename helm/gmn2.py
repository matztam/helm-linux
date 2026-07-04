"""GMN 2.0 transport framing + a pcap analyzer for the Helm control channel.

The Helm control port (the mDNS-advertised _garmin-helm._tcp port, e.g. 51200)
speaks **GMN 2.0** -- "Garmin Marine Network 2.0" -- an app-multiplexed binary
message protocol (native: msl/iop/net/trans/iop_net_grmn_trans_tcp.c). Native
diagnostics reveal the header fields:

    "Discarding packet with incomplete GMN 2.0 header (sz=%d)"
    "Discarding packet with invalid GMN 2.0 header (vrsn=%d, res=%d,
                                                     src app=%d, dst app=%d)"
    "Bad message header! Magic: %x Expected; %x"

So each GMN 2.0 frame is a small fixed header:
    magic       -- constant, sanity check
    version     -- 2 for GMN 2.0
    reserved
    src_app     -- source application id
    dst_app     -- destination application id
    length      -- payload byte count
    <payload>   -- the app message (Helm keys/touches/stream-url live here)

The EXACT widths/endianness/magic are confirmed from a real capture. This
module ships a best-fit parser with the layout as a single ``HEADER`` spec you
can adjust in one place after looking at your pcap, plus a heuristic
auto-detector that brute-forces the header layout from a captured stream so you
don't have to reverse it by hand.

Usage:
    python3 -m helm.gmn2 helm.pcap                 # analyze a capture
    python3 -m helm.gmn2 helm.pcap --port 51200    # focus on the control port
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Header layout. Adjust HEADER once you confirm bytes from a capture; the rest
# of the module (framing, reassembly) then works unchanged.
# Fields are (name, struct_code). '>' big-endian is Garmin's usual on-the-wire.
# Default guess: magic(u16) vrsn(u8) res(u8) src(u16) dst(u16) len(u16)
# ---------------------------------------------------------------------------
# CONFIRMED from libgmm.so (GMN 2.0 header validator, iop_net_grmn_trans_tcp.c):
# 8-byte little-endian header, no magic. Field offsets and widths verified by
# disassembly (ldrb [buf+0]=version, [buf+1]=reserved, ldrh [buf+2]=src_app,
# [buf+4]=dst_app, [buf+6]=length); parser requires >= 8 bytes.
ENDIAN = "<"
HEADER_FIELDS = [
    ("version", "B"),
    ("reserved", "B"),
    ("src_app", "H"),
    ("dst_app", "H"),
    ("length", "H"),
]


def _header_struct() -> struct.Struct:
    return struct.Struct(ENDIAN + "".join(code for _, code in HEADER_FIELDS))


HEADER = _header_struct()
HEADER_NAMES = [n for n, _ in HEADER_FIELDS]


@dataclass
class Gmn2Frame:
    fields: dict
    payload: bytes

    def __str__(self) -> str:
        f = " ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}"
                     for k, v in self.fields.items())
        return f"GMN2[{f}] payload={len(self.payload)}B: {self.payload[:32].hex()}"


HELM_MAGIC = 0xBEEF  # on wire: bytes ef be at header offset 2

# Known Helm message types (low 16 bits; observed in captures)
HELM_TYPES = {
    0x1649: "device_name",
    0x1648: "device_info",
    0x083f: "hello?",
    0x0aa9: "token?",
}


def parse_helm_frames(buf: bytes):
    """Parse the real :51200 Helm framing: [u16 type][u16 0xBEEF][u32 len LE][payload]."""
    off = 0
    n = len(buf)
    while off + 8 <= n:
        magic = int.from_bytes(buf[off + 2:off + 4], "little")
        if magic != HELM_MAGIC:
            nxt = buf.find(b"\xef\xbe", off + 1)  # resync to next 0xBEEF marker
            if nxt < 2:
                break
            off = nxt - 2
            continue
        typ = int.from_bytes(buf[off:off + 2], "little")
        length = int.from_bytes(buf[off + 4:off + 8], "little")
        if off + 8 + length > n:
            break
        payload = buf[off + 8:off + 8 + length]
        yield typ, payload
        off += 8 + length


MSG_MAGIC = b"MSG*"  # 0x2a47534d little-endian; helm session message framing


def parse_msg_frames(buf: bytes):
    """Parse the 'MSG*' message framing: magic(4) + length(4 LE) + payload."""
    off = 0
    while off + 8 <= len(buf):
        if buf[off:off + 4] != MSG_MAGIC:
            # resync to next magic if there's junk/interleaving
            nxt = buf.find(MSG_MAGIC, off + 1)
            if nxt < 0:
                break
            off = nxt
            continue
        length = int.from_bytes(buf[off + 4:off + 8], "little")
        if off + 8 + length > len(buf):
            break
        payload = buf[off + 8:off + 8 + length]
        yield {"length": length}, payload
        off += 8 + length


def parse_frames(buf: bytes, header: struct.Struct = HEADER):
    """Yield (Gmn2Frame, consumed) parsing as many frames as fit in buf."""
    off = 0
    hs = header.size
    while off + hs <= len(buf):
        vals = header.unpack_from(buf, off)
        fields = dict(zip(HEADER_NAMES, vals))
        length = fields.get("length", 0)
        if off + hs + length > len(buf):
            break
        payload = buf[off + hs: off + hs + length]
        yield Gmn2Frame(fields, payload)
        off += hs + length


# ---------------------------------------------------------------------------
# Heuristic layout auto-detection from a raw TCP stream (one direction).
# Tries endian + field widths and scores how cleanly the whole stream frames.
# ---------------------------------------------------------------------------

def autodetect_layout(stream: bytes):
    """Brute-force a header layout that frames ``stream`` end-to-end.

    Returns a list of (score, description, struct, length_field_offset) sorted
    best-first. 'score' = number of frames that tile the stream with no leftover.
    """
    candidates = []
    # header sizes 8..16, length field as u16/u32 at various offsets
    for endian in (">", "<"):
        for hsize in (8, 10, 12, 16):
            for loff in range(2, hsize - 1):
                for lcode, lsz in (("H", 2), ("I", 4)):
                    if loff + lsz > hsize:
                        continue
                    score, nframes = _score(stream, endian, hsize, loff, lcode)
                    if score > 0:
                        desc = (f"endian={endian} hdr={hsize}B "
                                f"len@{loff}:{lcode}")
                        candidates.append((score, nframes, desc, endian,
                                           hsize, loff, lcode))
    candidates.sort(reverse=True)
    return candidates


def _score(stream, endian, hsize, loff, lcode):
    off = 0
    n = 0
    L = len(stream)
    lstruct = struct.Struct(endian + lcode)
    magics = {}
    while off + hsize <= L:
        (length,) = lstruct.unpack_from(stream, off + loff)
        if length > 0x100000:  # implausible frame
            return (0, 0)
        end = off + hsize + length
        if end > L:
            break
        magics[stream[off:off + 2]] = magics.get(stream[off:off + 2], 0) + 1
        off = end
        n += 1
    # perfect tiling (no trailing bytes) with a stable magic scores highest
    if n >= 2 and off == L:
        stable_magic = max(magics.values()) if magics else 0
        return (n * 10 + stable_magic, n)
    if n >= 2 and L - off < hsize:
        return (n, n)
    return (0, 0)


# ---------------------------------------------------------------------------
# pcap reading (pure Python; supports classic pcap and pcapng lightly)
# ---------------------------------------------------------------------------

def read_pcap_tcp(path: str, focus_port: int | None = None):
    """Yield (src, sport, dst, dport, payload) for TCP segments in a pcap."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        yield from _read_classic_pcap(data, focus_port)
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data, focus_port)
    else:
        raise ValueError("Unrecognized capture format (need pcap or pcapng)")


def _iter_tcp(linktype, endian, pkt, focus_port):
    # Ethernet(1)/raw/Linux SLL minimal handling
    off = 0
    if linktype == 1:  # Ethernet
        if len(pkt) < 14:
            return
        eth = struct.unpack(">H", pkt[12:14])[0]
        off = 14
        if eth == 0x8100:  # VLAN
            eth = struct.unpack(">H", pkt[16:18])[0]
            off = 18
        if eth != 0x0800:
            return
    elif linktype == 113:  # Linux cooked SLL
        if len(pkt) < 16:
            return
        if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
            return
        off = 16
    elif linktype in (101, 12, 14):  # raw IP
        off = 0
    else:
        return
    ip = pkt[off:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return
    ihl = (ip[0] & 0xF) * 4
    if ip[9] != 6:  # not TCP
        return
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return
    sport, dport = struct.unpack(">HH", tcp[0:4])
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    if focus_port and focus_port not in (sport, dport):
        return
    if payload:
        yield (src, sport, dst, dport, payload)


def _read_classic_pcap(data, focus_port):
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _ts, _us, caplen, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        yield from _iter_tcp(linktype, endian, pkt, focus_port)


def _read_pcapng(data, focus_port):
    off = 0
    endian = "<"
    linktype = 1
    while off + 12 <= len(data):
        btype, blen = struct.unpack(endian + "II", data[off:off + 8])
        if btype == 0x0A0D0D0A:  # section header, detect endianness via BOM
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            btype, blen = struct.unpack(endian + "II", data[off:off + 8])
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # interface description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
        elif btype == 0x00000006:  # enhanced packet block
            caplen = struct.unpack(endian + "I", body[12:16])[0]
            pkt = body[20:20 + caplen]
            yield from _iter_tcp(linktype, endian, pkt, focus_port)
        elif btype == 0x00000003:  # simple packet block
            pkt = body[4:]
            yield from _iter_tcp(linktype, endian, pkt, focus_port)
        off += blen


# ---------------------------------------------------------------------------
# CLI: reassemble each TCP stream and try to frame it as GMN 2.0
# ---------------------------------------------------------------------------

def analyze(path: str, focus_port: int | None = None) -> int:
    streams: dict[tuple, bytearray] = {}
    for src, sp, dst, dp, payload in read_pcap_tcp(path, focus_port):
        streams.setdefault((src, sp, dst, dp), bytearray()).extend(payload)
    if not streams:
        print("No TCP payload found (check --port / that the capture has data).")
        return 1

    for key, buf in sorted(streams.items(), key=lambda kv: -len(kv[1])):
        src, sp, dst, dp = key
        print(f"\n=== {src}:{sp} -> {dst}:{dp}  ({len(buf)} bytes) ===")
        head = bytes(buf[:64])
        print("first bytes:", head.hex())
        # Real Helm :51200 framing: [u16 type][u16 0xBEEF][u32 len][payload]
        if b"\xef\xbe" in buf[:512]:
            hframes = list(parse_helm_frames(bytes(buf)))
            if hframes:
                print(f"  HELM 0xBEEF framing: {len(hframes)} messages")
                from collections import Counter
                types = Counter(t for t, _ in hframes)
                print("    type histogram: " +
                      ", ".join(f"0x{t:04x}({HELM_TYPES.get(t,'?')})×{c}"
                                for t, c in types.most_common(12)))
                for typ, payload in hframes[:40]:
                    name = HELM_TYPES.get(typ, "?")
                    ap = "".join(chr(c) if 32 <= c < 127 else "." for c in payload[:56])
                    print(f"    0x{typ:04x} {name:12} len={len(payload):<5} "
                          f"{payload[:40].hex()}  {ap}")
                    for m in (b"rtsp://", b"http://", b"mjpg", b".sdp"):
                        i = payload.lower().find(m)
                        if i >= 0:
                            e = i
                            while e < len(payload) and 32 < payload[e] < 127 and payload[e] not in b'"\',':
                                e += 1
                            print(f"        >>> URL: {payload[i:e].decode('ascii','replace')}")
                continue
        # MSG* session framing (older/other services)
        if MSG_MAGIC in buf[:256]:
            msgs = list(parse_msg_frames(bytes(buf)))
            if msgs:
                print(f"  MSG* framing: {len(msgs)} messages")
                for fields, payload in msgs[:16]:
                    ascii_prev = "".join(chr(c) if 32 <= c < 127 else "."
                                         for c in payload[:48])
                    print(f"    MSG* len={fields['length']}: "
                          f"{payload[:48].hex()}  {ascii_prev}")
                    for m in (b"rtsp://", b"http://", b"mjpg"):
                        i = payload.lower().find(m)
                        if i >= 0:
                            e = i
                            while e < len(payload) and 32 < payload[e] < 127 and payload[e] not in b'"\',':
                                e += 1
                            print(f"        >>> URL: {payload[i:e].decode('ascii','replace')}")
                continue
        # Is it plaintext (TLS starts with 0x16 0x03)? Note if encrypted.
        if buf[:1] == b"\x16" and buf[1:2] == b"\x03":
            print("  -> looks like TLS ClientHello; control may be TLS-wrapped.")
        # try the configured HEADER first
        frames = list(parse_frames(bytes(buf)))
        if frames and sum(HEADER.size + len(f.payload) for f in frames) >= len(buf) - HEADER.size:
            print(f"  framed with default HEADER as {len(frames)} GMN2 frames:")
            for fr in frames[:12]:
                print("   ", fr)
        else:
            print("  default HEADER didn't tile cleanly; auto-detecting layout...")
            cands = autodetect_layout(bytes(buf))
            for score, nf, desc, *_ in cands[:5]:
                print(f"    candidate: {desc}  -> {nf} frames (score {score})")
            if not cands:
                print("    no clean binary framing (encrypted? or app-layer differs)")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Analyze GMN 2.0 / Helm control pcap")
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, help="focus on this TCP port (e.g. 51200)")
    args = ap.parse_args()
    sys.exit(analyze(args.pcap, args.port))
