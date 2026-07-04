"""Experimental GMN 2.0 Helm session probe (:51200).

Now that this laptop is a registered bl-id/user on the plotter, the Helm GMN 2.0
port may talk to us where it reset an unregistered client before. This probe
opens the connection, listens for anything the plotter volunteers, and tries a
minimal GMN 2.0 client frame, decoding replies with helm.gmn2.

It is a diagnostic: it tells us whether registration changed the plotter's
behavior and captures the first bytes of the real handshake so we can implement
the session for-real (app-id registration -> device list -> stream URL ->
keys/touches). Pair + grant "View and Control" on the plotter first.
"""

from __future__ import annotations

import socket
import time

from . import gmn2


def _hexdump(b: bytes, n: int = 96) -> str:
    return b[:n].hex()


def _fresh(host, port, timeout=4.0):
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    return s


def _try(host, port, label, payload, wait_first=False):
    """Open a fresh socket, optionally read first, send payload, read reply."""
    try:
        s = _fresh(host, port)
    except OSError as e:
        print(f"  [{label}] connect failed: {e}")
        return None
    try:
        if wait_first:
            s.settimeout(2.0)
            try:
                first = s.recv(4096)
                if first:
                    print(f"  [{label}] server spoke first: {_hexdump(first)}")
                    return first
            except socket.timeout:
                pass
        if payload:
            s.sendall(payload)
        s.settimeout(2.5)
        reply = s.recv(4096)
        if reply:
            print(f"  [{label}] reply {len(reply)}B: {_hexdump(reply)}")
            txt = reply[:64].decode("latin1").replace("\r", "\\r").replace("\n", "\\n")
            print(f"          ascii: {txt}")
            return reply
        print(f"  [{label}] empty reply / closed")
    except ConnectionResetError:
        print(f"  [{label}] RST (server rejected/closed)")
    except (socket.timeout, OSError) as e:
        print(f"  [{label}] {type(e).__name__}: {e}")
    finally:
        s.close()
    return None


def connect_probe(host: str, port: int = 51200, timeout: float = 6.0) -> int:
    print(f"Fingerprinting {host}:{port} (fresh socket per probe)\n")

    # 1) does it volunteer a banner?
    _try(host, port, "listen", b"", wait_first=True)

    # 2) RTSP? (Garmin Helm video is RTSP; port may be non-standard)
    rtsp = (f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\nCSeq: 1\r\n"
            "User-Agent: garmin-helm-linux\r\n\r\n").encode()
    _try(host, port, "RTSP-OPTIONS", rtsp)

    # 3) HTTP? (maybe websocket-upgrade / REST)
    http = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    _try(host, port, "HTTP-GET", http)

    # 4) GMN 2.0 frames: sweep version byte and a nonzero src app id.
    for ver in (1, 2, 3):
        payload = gmn2.HEADER.pack(ver, 0, 1, 1, 0)  # ver,res,src=1,dst=1,len=0
        _try(host, port, f"GMN2 v{ver} src1 dst1", payload)

    # 5) "MSG*" message framing (magic 0x2a47534d, disassembled): magic + len32.
    MSG = b"MSG*"  # 4d 53 47 2a
    _try(host, port, "MSG* len=0", MSG + (0).to_bytes(4, "little"))
    # MSG* header followed by a tiny GMN2-ish body of declared length
    body = gmn2.HEADER.pack(2, 0, 1, 1, 0)
    _try(host, port, "MSG* +gmn2body",
         MSG + len(body).to_bytes(4, "little") + body)
    # and the big-endian length interpretation, just in case
    _try(host, port, "MSG* len=0 BE", MSG + (0).to_bytes(4, "big"))

    print("\nWhichever probe gets a non-RST reply tells us what :51200 speaks:\n"
          "  RTSP reply -> video is here, we're basically done (RTSP is built)\n"
          "  HTTP reply -> REST/websocket control\n"
          "  binary reply -> GMN2; the bytes show the real header/version\n"
          "  all RST      -> needs the exact first frame; one capture nails it")
    return 0


def _decode(b: bytes) -> None:
    if b[:1] == b"\x16" and b[1:2] == b"\x03":
        print("    (looks like TLS)")
        return
    frames = list(gmn2.parse_frames(b))
    for f in frames[:6]:
        print("    GMN2:", f)
    if not frames:
        cands = gmn2.autodetect_layout(b)
        for sc, nf, desc, *_ in cands[:3]:
            print(f"    framing candidate: {desc} -> {nf} frames")


if __name__ == "__main__":
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "172.16.6.0"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 51200
    raise SystemExit(connect_probe(h, p))
