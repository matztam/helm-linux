"""Probe the Helm control port directly from this machine.

Run this against the plotter (the mDNS-advertised _garmin-helm._tcp host:port,
e.g. 172.16.6.0:51200) to learn, without needing the phone:
  * whether the port accepts TCP connections at all,
  * whether it sends an unsolicited banner/hello on connect (GMN 2.0 servers
    often do),
  * whether the channel is plaintext GMN 2.0 or TLS-encrypted (which decides
    whether a passive capture can ever reveal the protocol).

This does NOT authenticate; it just characterizes the endpoint.
"""

from __future__ import annotations

import socket
import sys

from . import gmn2


def probe(host: str, port: int, timeout: float = 4.0) -> int:
    print(f"Connecting to {host}:{port} ...")
    try:
        s = socket.create_connection((host, port), timeout)
    except OSError as e:
        print(f"  connect failed: {e}")
        return 1
    print("  connected.")
    s.settimeout(timeout)

    # 1) Does the server speak first (banner / GMN2 hello)?
    banner = b""
    try:
        banner = s.recv(4096)
    except socket.timeout:
        pass
    if banner:
        print(f"  server sent {len(banner)} bytes on connect:")
        print("    hex:", banner[:80].hex())
        _classify(banner)
        # try to frame it as GMN 2.0
        frames = list(gmn2.parse_frames(banner))
        if frames:
            print("  frames as GMN 2.0:")
            for fr in frames[:6]:
                print("   ", fr)
        else:
            cands = gmn2.autodetect_layout(banner)
            if cands:
                print("  auto-detected framing candidates:")
                for sc, nf, desc, *_ in cands[:3]:
                    print(f"    {desc} -> {nf} frames")
    else:
        print("  server said nothing on connect (waits for client hello).")

    # 2) Is it TLS? Send a TLS ClientHello and see if we get a ServerHello.
    s.close()
    _tls_check(host, port, timeout)
    return 0


def _classify(data: bytes) -> None:
    if data[:1] == b"\x16" and data[1:2] == b"\x03":
        print("    -> looks like TLS (handshake record). Channel is encrypted.")
    elif data[:4].isascii() and data[:4].isupper():
        print(f"    -> ascii-ish header: {data[:16]!r}")
    else:
        print(f"    -> binary; first 2 bytes (possible magic): {data[:2].hex()}")


def _tls_check(host: str, port: int, timeout: float) -> None:
    # Minimal TLS 1.2 ClientHello; if the peer responds with a TLS record
    # (0x16 handshake or 0x15 alert), it's speaking TLS.
    import os

    hello_body = (
        b"\x03\x03" + os.urandom(32) + b"\x00" +
        b"\x00\x02\x00\x2f" +          # 1 cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
        b"\x01\x00" +                  # compression: null
        b"\x00\x00"                    # extensions length 0
    )
    hs = b"\x01\x00" + len(hello_body).to_bytes(2, "big") + hello_body
    rec = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        s.sendall(rec)
        resp = s.recv(16)
        s.close()
    except OSError as e:
        print(f"  TLS probe: no response ({e})")
        return
    if resp[:1] in (b"\x16", b"\x15", b"\x14"):
        print("  TLS probe: peer replied with a TLS record -> control channel is TLS.")
        print("    A passive pcap won't show plaintext; capture must come from the")
        print("    phone side (PCAPdroid) or via app instrumentation.")
    elif resp:
        print(f"  TLS probe: peer replied non-TLS ({resp[:8].hex()}) -> likely plaintext GMN 2.0.")
    else:
        print("  TLS probe: no reply.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m helm.probe_control <host> [port]")
        raise SystemExit(2)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 51200
    raise SystemExit(probe(host, port))
