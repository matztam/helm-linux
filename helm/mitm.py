"""Plaintext MITM proxy for the Helm (GMN 2.0) control channel.

The control channel is unencrypted GMN 2.0 and the laptop can reach the plotter,
so the cleanest way to learn the full protocol -- the authenticated handshake,
the video stream URL, and the live key/touch frames -- is to sit in the middle:

    phone  --->  this proxy (laptop)  --->  real plotter
                 (decodes + logs)

We advertise a second _garmin-helm._tcp service from the laptop so the phone's
Helm device list shows it; you pick it, and every byte flows through here in
plaintext. No root, no monitor mode, no fighting PCAPdroid's mDNS problem.

Run:
    python3 -m helm.mitm --plotter 172.16.6.0 --port 51200 --name "Helm (proxy)"

Then on the phone: open ActiveCaptain -> Helm, pick the "Helm (proxy)" device,
and drive it. Watch this console. A full transcript is saved to helm-mitm.log
(decoded) and helm-mitm-<dir>.bin (raw streams) for offline analysis.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

from . import gmn2


def local_ip_toward(host: str) -> str:
    """Best-effort local IP on the same subnet as the plotter."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))
        return s.getsockname()[0]
    finally:
        s.close()


class FrameLogger:
    """Reassembles one direction and logs completed GMN 2.0 frames."""

    def __init__(self, tag: str, logfile, rawfile):
        self.tag = tag
        self.buf = bytearray()
        self.log = logfile
        self.raw = rawfile

    def feed(self, data: bytes):
        self.raw.write(data)
        self.raw.flush()
        self.buf.extend(data)
        self._drain()

    def _drain(self):
        hs = gmn2.HEADER.size
        while len(self.buf) >= hs:
            vals = gmn2.HEADER.unpack_from(self.buf, 0)
            fields = dict(zip(gmn2.HEADER_NAMES, vals))
            length = fields["length"]
            if hs + length > len(self.buf):
                break
            payload = bytes(self.buf[hs:hs + length])
            del self.buf[:hs + length]
            self._emit(fields, payload)

    def _emit(self, fields, payload):
        ts = time.strftime("%H:%M:%S")
        hdr = (f"v{fields['version']} res{fields['reserved']} "
               f"src={fields['src_app']} dst={fields['dst_app']} "
               f"len={fields['length']}")
        ascii_preview = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload[:80]
        )
        line = f"[{ts}] {self.tag} {hdr}\n    hex: {payload[:96].hex()}\n    txt: {ascii_preview}"
        interesting = self._highlight(payload)
        if interesting:
            line += "\n    >>> " + interesting
        print(line)
        self.log.write(line + "\n")
        self.log.flush()

    @staticmethod
    def _highlight(payload: bytes) -> str:
        notes = []
        low = payload.lower()
        for marker in (b"rtsp://", b"http://", b"mjpg", b".sdp"):
            i = low.find(marker)
            if i >= 0:
                end = i
                while end < len(payload) and 32 < payload[end] < 127 and payload[end] not in b'"\',;)]}':
                    end += 1
                notes.append(f"STREAM URL: {payload[i:end].decode('ascii','replace')}")
        j = payload.find(b"eyJ")  # JWT
        if j >= 0:
            end = j
            while end < len(payload) and payload[end] not in b'"\x00 ':
                end += 1
            notes.append(f"JWT: {payload[j:min(end, j+60)].decode('ascii','replace')}...")
        return " | ".join(notes)


def relay(src: socket.socket, dst: socket.socket, logger: FrameLogger, stop):
    try:
        while not stop.is_set():
            data = src.recv(65536)
            if not data:
                break
            logger.feed(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        stop.set()


def handle_client(client: socket.socket, caddr, plotter, pport, logf, rawpfx):
    print(f"\n=== phone {caddr} connected; dialing plotter {plotter}:{pport} ===")
    try:
        upstream = socket.create_connection((plotter, pport), 10)
    except OSError as e:
        print(f"  cannot reach plotter: {e}")
        client.close()
        return
    stop = threading.Event()
    raw_p2s = open(f"{rawpfx}-phone2plotter.bin", "ab")
    raw_s2p = open(f"{rawpfx}-plotter2phone.bin", "ab")
    lg_p2s = FrameLogger("PHONE->PLOTTER", logf, raw_p2s)
    lg_s2p = FrameLogger("PLOTTER->PHONE", logf, raw_s2p)
    t1 = threading.Thread(target=relay, args=(client, upstream, lg_p2s, stop), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client, lg_s2p, stop), daemon=True)
    t1.start(); t2.start()
    stop.wait()
    for s in (client, upstream):
        try: s.close()
        except OSError: pass
    raw_p2s.close(); raw_s2p.close()
    print(f"=== session {caddr} closed ===")


def advertise(name: str, ip: str, port: int):
    """Advertise a _garmin-helm._tcp service via zeroconf, if available."""
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        print("NOTE: python 'zeroconf' not installed, cannot auto-advertise the")
        print("      proxy on the phone's Helm list. Install it:")
        print("          pip install --break-system-packages zeroconf")
        print("      or redirect the phone another way (ARP spoof / manual).")
        return None
    info = ServiceInfo(
        "_garmin-helm._tcp.local.",
        f"{name}._garmin-helm._tcp.local.",
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties={"version": "4"},
        server=f"helmproxy-{port}.local.",
    )
    zc = Zeroconf()
    zc.register_service(info)
    print(f"Advertised '{name}' at {ip}:{port} as _garmin-helm._tcp")
    return zc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Helm GMN2 MITM proxy")
    ap.add_argument("--plotter", required=True, help="real plotter IP (from discover)")
    ap.add_argument("--port", type=int, default=51200, help="plotter Helm port")
    ap.add_argument("--listen", type=int, default=0, help="local listen port (default: same as --port)")
    ap.add_argument("--name", default="Helm (proxy)", help="name shown on the phone")
    ap.add_argument("--ip", help="laptop IP to advertise (default: auto)")
    ap.add_argument("--log", default="helm-mitm.log")
    ap.add_argument("--raw-prefix", default="helm-mitm")
    args = ap.parse_args(argv)

    listen_port = args.listen or args.port
    ip = args.ip or local_ip_toward(args.plotter)
    logf = open(args.log, "a")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", listen_port))
    srv.listen(4)
    print(f"Proxy listening on {ip}:{listen_port} -> plotter {args.plotter}:{args.port}")
    print(f"Decoded transcript: {args.log}   raw: {args.raw_prefix}-*.bin")

    zc = advertise(args.name, ip, listen_port)
    print("\nOn the phone: ActiveCaptain -> Helm -> pick "
          f"'{args.name}'. Then press keys / tap. Ctrl-C to stop.\n")
    try:
        while True:
            client, caddr = srv.accept()
            threading.Thread(
                target=handle_client,
                args=(client, caddr, args.plotter, args.port, logf, args.raw_prefix),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        if zc:
            zc.close()
        srv.close()
        logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
