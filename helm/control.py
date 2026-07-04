"""Control channel: send keys and touches to the plotter.

STATUS
------
Video and discovery are standard protocols and work today. The *control*
channel (keys/touches) is Garmin-proprietary. In the app it is
``HelmClientManager.nativeSendKeys`` / ``nativeSendTouches``, implemented deep
in libgmm.so inside the VCM ("Vessel Connect Manager") subsystem
(msl/vcm/client/helm/vcm_helm_state.c). It rides an authenticated app-to-app
message bus (JWT auth under msl/vcm/Auth/*), and its exact framing is not
recoverable from static strings alone.

This module therefore provides:
  * A correct, verified *model* of what must be sent (helm.keys.HelmKey /
    HelmTouch) -- the payload semantics, transcribed from the app.
  * A pure-Python RTSP probe (OPTIONS/DESCRIBE) that DOES work: it fetches the
    plotter's SDP so you can confirm the codec and derive the exact stream URL.
  * A pluggable Transport abstraction with two experimental hypotheses and a
    default that tells you exactly what to capture to finalize it.

Use helm.capture to record one real key/touch from the phone, drop the framing
into a Transport subclass, and control is complete. See PROTOCOL.md.
"""

from __future__ import annotations

import socket
from typing import Iterable, Protocol

from .keys import HelmKey, HelmTouch


# ----------------------------------------------------------------------------
# RTSP probe -- this part genuinely works against the plotter's RTSP server.
# ----------------------------------------------------------------------------

class RtspProbe:
    """Minimal RTSP client: OPTIONS + DESCRIBE to fetch the SDP.

    Enough to confirm the video track (H.264 vs MJPEG) and read the exact media
    URL the plotter serves, without launching a full player.
    """

    def __init__(self, url: str, timeout: float = 5.0):
        self.url = url
        self.timeout = timeout
        self.cseq = 0
        host, port, path = self._split(url)
        self.host, self.port, self.path = host, port, path

    @staticmethod
    def _split(url: str) -> tuple[str, int, str]:
        rest = url.split("://", 1)[-1]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        return host, int(port or 554), "/" + path

    def _request(self, sock: socket.socket, method: str, extra: str = "") -> str:
        self.cseq += 1
        req = (
            f"{method} {self.url} RTSP/1.0\r\n"
            f"CSeq: {self.cseq}\r\n"
            f"User-Agent: garmin-helm-linux\r\n"
            f"{extra}\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(self.timeout)
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            blob = b"".join(chunks)
            if b"\r\n\r\n" in blob:
                head, _, body = blob.partition(b"\r\n\r\n")
                clen = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        clen = int(line.split(b":", 1)[1])
                if len(body) >= clen:
                    break
        return b"".join(chunks).decode("utf-8", "replace")

    def describe(self) -> dict:
        """Return {'options': [...], 'sdp': str, 'codecs': [...]}"""
        with socket.create_connection((self.host, self.port), self.timeout) as s:
            opt = self._request(s, "OPTIONS")
            options = []
            for line in opt.split("\r\n"):
                if line.lower().startswith("public:"):
                    options = [m.strip() for m in line.split(":", 1)[1].split(",")]
            desc = self._request(s, "DESCRIBE", "Accept: application/sdp\r\n")
            _, _, sdp = desc.partition("\r\n\r\n")
            codecs = []
            for line in sdp.split("\n"):
                line = line.strip()
                if line.startswith("a=rtpmap:"):
                    codecs.append(line.split(" ", 1)[-1])
                if line.startswith("m="):
                    codecs.append(line)
            return {"options": options, "sdp": sdp, "codecs": codecs}


# ----------------------------------------------------------------------------
# Control transport -- pluggable; finalize against a real capture.
# ----------------------------------------------------------------------------

class Transport(Protocol):
    def send_keys(self, device_id: int, keys: list[HelmKey]) -> None: ...
    def send_touches(self, device_id: int, touches: list[HelmTouch]) -> None: ...
    def close(self) -> None: ...


class CaptureNeededTransport:
    """Default transport. Does not guess a wire format; instead it prints the
    exact semantic payload and tells you what to capture to finish the job."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def _explain(self, kind: str, payload) -> None:
        print(f"[control:{kind}] to {self.host}:{self.port} -> {payload}")
        print(
            "  This is the semantic payload. The exact VCM framing is not yet "
            "wired up.\n"
            "  Run:  python -m helm.capture --host %s   (with the phone app "
            "controlling the plotter)\n"
            "  then drop the observed framing into a Transport subclass. "
            "See PROTOCOL.md." % self.host
        )

    def send_keys(self, device_id: int, keys: list[HelmKey]) -> None:
        self._explain("keys", [(k.name, int(k)) for k in keys])

    def send_touches(self, device_id: int, touches: list[HelmTouch]) -> None:
        self._explain("touches", [t.as_dict() for t in touches])

    def close(self) -> None:
        pass


class RtspSetParameterTransport:
    """EXPERIMENTAL hypothesis: control multiplexed over RTSP SET_PARAMETER.

    Some remote-screen protocols push input as RTSP SET_PARAMETER bodies on the
    same session as the video. Unconfirmed for Garmin -- included so it can be
    tried and either validated or discarded against a real device."""

    def __init__(self, rtsp_url: str, timeout: float = 5.0):
        self.probe = RtspProbe(rtsp_url, timeout)
        self.rtsp_url = rtsp_url
        self._sock: socket.socket | None = None
        self._cseq = 0

    def _conn(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.create_connection(
                (self.probe.host, self.probe.port), self.probe.timeout
            )
        return self._sock

    def _set_parameter(self, body: str) -> None:
        s = self._conn()
        self._cseq += 1
        req = (
            f"SET_PARAMETER {self.rtsp_url} RTSP/1.0\r\n"
            f"CSeq: {self._cseq}\r\n"
            f"Content-Type: text/parameters\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        )
        s.sendall(req.encode())

    def send_keys(self, device_id: int, keys: list[HelmKey]) -> None:
        body = "".join(f"key: {int(k)}\r\n" for k in keys)
        self._set_parameter(body)

    def send_touches(self, device_id: int, touches: list[HelmTouch]) -> None:
        body = "".join(
            f"touch: {t.track_id} {t.fixed_x} {t.fixed_y} {int(t.down)}\r\n"
            for t in touches
        )
        self._set_parameter(body)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None


class HelmControlClient:
    """High-level control API mirroring HelmClientManager.

    Encodes keys/touches with the correct model and dispatches through a
    Transport. Swap the transport once the VCM framing is captured.
    """

    def __init__(self, host: str, port: int, device_id: int = 0,
                 transport: Transport | None = None):
        self.host = host
        self.port = port
        self.device_id = device_id
        self.transport: Transport = transport or CaptureNeededTransport(host, port)

    # Mirrors HelmClientManager.sendKeys(deviceId, [HelmKey])
    def send_key(self, key: HelmKey) -> None:
        self.transport.send_keys(self.device_id, [key])

    def send_keys(self, keys: Iterable[HelmKey]) -> None:
        self.transport.send_keys(self.device_id, list(keys))

    # Mirrors HelmClientManager.sendTouches(deviceId, [HelmTouch])
    def send_touches(self, touches: Iterable[HelmTouch]) -> None:
        self.transport.send_touches(self.device_id, list(touches))

    def tap(self, x: float, y: float, track_id: int = 0) -> None:
        """Convenience: a press+release at normalized (x, y)."""
        self.send_touches([HelmTouch(track_id, x, y, True)])
        self.send_touches([HelmTouch(track_id, x, y, False)])

    def close(self) -> None:
        self.transport.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m helm.control <rtsp-url>   # probe SDP")
        raise SystemExit(2)
    info = RtspProbe(sys.argv[1]).describe()
    print("OPTIONS:", ", ".join(info["options"]) or "(none)")
    print("Media/codecs:")
    for c in info["codecs"]:
        print("   ", c)
    print("\n--- SDP ---")
    print(info["sdp"])
