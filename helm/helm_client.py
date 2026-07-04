"""Working Garmin Helm client — session, touch control, and video URL.

Reverse-engineered from a live capture of the ActiveCaptain app talking to a
GPSMAP 923. The Helm control session runs on the mDNS-advertised _garmin-helm
port (:51200) with this framing:

    frame  = [u16 type LE][u16 0xBEEF][u32 length LE][payload]

Opening handshake (client -> plotter):
    0x083f  payload 0x9531            session hello / protocol tag
    0x0aa9  8-byte session token      client-chosen session id
    0x1648  u32 index (repeated)      device select + data subscriptions

Input (client -> plotter):
    0x164c  touch: [u32 track][u32 1][u8 0][u32 x][u32 y][u32 down][pad3]
            x,y = normalized screen coords * 65536 (16.16 fixed), matching
            HelmClientManager.HelmTouch. down: 1=press/move, 0=release.

Video (plotter -> client): a standard RTSP/H.264 stream, its URL delivered in a
0x1649/subtype-0 message but also deterministic:
    rtsp://<plotter-host>:554/helm_1280x720.h264

Prereqs: this client must be a registered bl-id (see helm.credential / `pair`)
and the plotter's global App-permission must be View and Control.
"""

from __future__ import annotations

import os
import socket
import struct
import time

HELM_PORT = 51200
MAGIC = 0xBEEF
TOUCH_UNITY = 65536

# message types
T_HELLO = 0x083F
T_TOKEN = 0x0AA9
T_SUBSCRIBE = 0x1648
T_ACQUIRE = 0x1644   # empty: client requests a touch context
T_CONTEXT = 0x1645   # plotter reply: [u32 1][u32 touch_ctx_id] -- id for touches
T_TOUCH = 0x164C

HELLO_TAG = 0x9531  # payload of the 0x083f hello (2 bytes LE)

# Device-select + subscription indices the app sends, in order (from capture).
# 0x0b selects the plotter; the rest subscribe to data/pages. Replaying the
# full set matches the app exactly.
SUBSCRIBE_INDICES = [0x0b, 0x00, 0x01, 0x06, 0x08, 0x0a, 0x03, 0x04, 0x05,
                     0x09, 0x01, 0x08, 0x00, 0x0a, 0x02, 0x0c]


def _frame(mtype: int, payload: bytes = b"") -> bytes:
    return struct.pack("<HHI", mtype, MAGIC, len(payload)) + payload


def encode_touch(ctx: bytes, x: float, y: float, down: bool) -> bytes:
    """Build a 0x164c touch payload. ``ctx`` = the 4-byte touch context id the
    plotter assigned (0x1645). x,y normalized [0,1] from the top-left."""
    xf = max(0, min(TOUCH_UNITY, int(x * TOUCH_UNITY)))
    yf = max(0, min(TOUCH_UNITY, int(y * TOUCH_UNITY)))
    # [ctx:4][u32 1][u8 0][u32 x][u32 y][u32 down][pad:3]
    return ctx[:4] + struct.pack("<IBIII", 1, 0, xf, yf, 1 if down else 0) + b"\x00\x00\x00"


class HelmClient:
    def __init__(self, host: str, port: int = HELM_PORT, token: bytes | None = None):
        self.host = host
        self.port = port
        self.token = token or os.urandom(8)
        self.sock: socket.socket | None = None
        self.touch_ctx: bytes | None = None  # assigned by plotter (0x1645)
        self._rxbuf = bytearray()

    @property
    def rtsp_url(self) -> str:
        return f"rtsp://{self.host}:554/helm_1280x720.h264"

    def connect(self, timeout: float = 6.0) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout)
        self.sock.settimeout(timeout)
        self._handshake()

    def _send(self, mtype: int, payload: bytes = b"") -> None:
        assert self.sock is not None, "not connected"
        self.sock.sendall(_frame(mtype, payload))

    def _handshake(self) -> None:
        self._send(T_HELLO, struct.pack("<H", HELLO_TAG))
        self._send(T_TOKEN, self.token)
        for idx in SUBSCRIBE_INDICES:
            self._send(T_SUBSCRIBE, struct.pack("<I", idx))
        self._send(T_ACQUIRE)                 # request a touch context
        self.touch_ctx = self._await_context()  # read the 0x1645 reply

    def _await_context(self, timeout: float = 3.0):
        """Read frames until the plotter's 0x1645 assigns our touch id."""
        import time
        from . import gmn2
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.1, deadline - time.time()))
                chunk = self.sock.recv(16384)
            except OSError:
                break
            if not chunk:
                break
            self._rxbuf.extend(chunk)
            consumed = 0
            for typ, pl in gmn2.parse_helm_frames(bytes(self._rxbuf)):
                consumed += 8 + len(pl)
                if typ == T_CONTEXT and len(pl) >= 8:
                    del self._rxbuf[:consumed]
                    return bytes(pl[4:8])
            # keep only a tail if nothing found yet (avoid unbounded growth)
            if len(self._rxbuf) > 1 << 20:
                del self._rxbuf[:-4096]
        return None

    # ---- input -----------------------------------------------------------
    def touch(self, x: float, y: float, down: bool, new_gesture: bool = False) -> None:
        if not self.touch_ctx:
            raise RuntimeError("no touch context (plotter didn't send 0x1645) — "
                               "control not granted?")
        self._send(T_TOUCH, encode_touch(self.touch_ctx, x, y, down))

    def tap(self, x: float, y: float) -> None:
        """A press+release at normalized (x, y)."""
        self.touch(x, y, True, new_gesture=True)
        time.sleep(0.02)
        self.touch(x, y, False)

    def drag(self, points, step_delay: float = 0.03) -> None:
        """points: iterable of (x, y) normalized; press, move through, release."""
        pts = list(points)
        if not pts:
            return
        self.touch(*pts[0], down=True, new_gesture=True)
        for p in pts[1:]:
            time.sleep(step_delay)
            self.touch(*p, down=True)
        time.sleep(step_delay)
        self.touch(*pts[-1], down=False)

    def read(self, n: int = 4096, timeout: float = 1.0) -> bytes:
        """Read whatever the plotter sends (device info, ack, etc.)."""
        assert self.sock is not None
        if self._rxbuf:  # return any bytes left over from the handshake first
            out = bytes(self._rxbuf); self._rxbuf.clear(); return out
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "172.16.6.0"
    c = HelmClient(host)
    print(f"connecting to {host}:{HELM_PORT} ...")
    c.connect()
    print("handshake sent. reading reply (device info)...")
    data = c.read(8192, timeout=2.0)
    print(f"  got {len(data)} bytes")
    if data:
        from . import gmn2
        for typ, pl in list(gmn2.parse_helm_frames(data))[:8]:
            ap = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:48])
            print(f"    0x{typ:04x} len={len(pl)} {pl[:40].hex()} {ap}")
    print(f"\nvideo: {c.rtsp_url}")
    print("sending a test tap at center (0.5, 0.5) ...")
    c.tap(0.5, 0.5)
    time.sleep(0.5)
    c.close()
    print("done.")
