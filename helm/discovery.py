"""mDNS discovery of Garmin Helm services.

The ActiveCaptain app finds chartplotters by browsing the Bonjour/mDNS service
type ``_garmin-helm._tcp.local`` (native code: vcm_service_discovery.c). Each
plotter that offers the Helm feature advertises a service record with its
hostname, IPv4 address, TCP port and a set of TXT key/value pairs (and a
protocol version, logged natively as: "Helm service added: %s %s:%d version:%d").

This module reimplements that browse in pure Python (standard library only) so
it runs on any Linux box without avahi/zeroconf installed. If the optional
``zeroconf`` package IS installed it is used instead, because it is more robust
on networks with many responders.

Related Garmin service types you may also see on a boat network:
    _garmin-helm._tcp     Helm remote view/control (what we want)
    _garmin-bl-app._tcp   BlueLink app messaging bus
    _garmin-marine._udp   general marine network announce
    _garmin-mrn-html._tcp  on-device HTML/web UI
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

HELM_SERVICE = "_garmin-helm._tcp.local"
CRED_SERVICE = "_garmin-mrn-cred._tcp.local"   # marine credential service (pairing)
GARMIN_SERVICE_TYPES = [
    "_garmin-helm._tcp.local",
    "_garmin-mrn-cred._tcp.local",   # credential service -> issues the auth token
    "_garmin-bl-id._tcp.local",      # BlueLink identity
    "_garmin-bl-app._tcp.local",     # BlueLink app messaging bus
    "_garmin-mrn-html._tcp.local",   # on-device web UI
    "_garmin-marine._udp.local",     # marine network announce
]

# DNS record types
_A = 1
_PTR = 12
_TXT = 16
_SRV = 33


@dataclass
class HelmService:
    """A discovered Garmin service instance."""

    instance: str  # full instance name, e.g. "GPSMAP 1243xsv._garmin-helm._tcp.local"
    service_type: str
    host: str = ""  # target hostname, e.g. "gpsmap-1243.local"
    address: str = ""  # resolved IPv4
    port: int = 0
    txt: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Human name (the instance label before the service type)."""
        return self.instance.split("._garmin", 1)[0]

    @property
    def rtsp_hint(self) -> str | None:
        """Best-guess RTSP URL from TXT records, if the device advertises one."""
        for key in ("rtsp", "stream", "streamurl", "url", "path"):
            if key in self.txt:
                v = self.txt[key]
                if v.startswith("rtsp://"):
                    return v
                if v.startswith("/") and self.address:
                    return f"rtsp://{self.address}:{self.port}{v}"
        return None

    def __str__(self) -> str:
        loc = f"{self.address or self.host}:{self.port}"
        extra = " ".join(f"{k}={v}" for k, v in self.txt.items())
        return f"{self.name}  [{loc}]  {extra}".rstrip()


# ----------------------------------------------------------------------------
# DNS message encoding / decoding (just enough of RFC 1035 for mDNS browse)
# ----------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("utf-8")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    pos = offset
    seen = 0
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
            pos = pointer
            jumped = True
            seen += 1
            if seen > 128:  # loop guard
                break
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("utf-8", "replace"))
        pos += length
        if not jumped:
            next_offset = pos
    return ".".join(labels), next_offset


def _build_query(service_types: list[str]) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, len(service_types), 0, 0, 0)
    body = bytearray()
    for st in service_types:
        body += _encode_name(st)
        body += struct.pack(">HH", _PTR, 0x8001)  # QTYPE=PTR, QU + IN class
    return header + bytes(body)


def _parse_records(data: bytes) -> list[tuple[str, int, bytes, int]]:
    """Return list of (name, rtype, rdata, rdata_offset) for every RR in a message."""
    if len(data) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    pos = 12
    for _ in range(qd):  # skip questions
        _, pos = _decode_name(data, pos)
        pos += 4
    records = []
    total = an + ns + ar
    for _ in range(total):
        if pos >= len(data):
            break
        name, pos = _decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        records.append((name, rtype, rdata, pos))
        pos += rdlen
    return records


def _parse_txt(rdata: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        chunk = rdata[i:i + length]
        i += length
        if not chunk:
            continue
        if b"=" in chunk:
            k, v = chunk.split(b"=", 1)
            out[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
        else:
            out[chunk.decode("utf-8", "replace")] = ""
    return out


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def browse(
    service_types: list[str] | None = None,
    timeout: float = 4.0,
    prefer_zeroconf: bool = True,
) -> list[HelmService]:
    """Browse the network for Garmin services. Returns a list of HelmService.

    Defaults to just the Helm service type. Pass GARMIN_SERVICE_TYPES to see
    everything Garmin on the network.
    """
    types = service_types or [HELM_SERVICE]
    if prefer_zeroconf:
        try:
            return _browse_zeroconf(types, timeout)
        except ImportError:
            pass
    return _browse_raw(types, timeout)


def _browse_raw(service_types: list[str], timeout: float) -> list[HelmService]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.bind(("", MDNS_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(0.5)

    query = _build_query(service_types)
    sock.sendto(query, (MDNS_ADDR, MDNS_PORT))

    # Accumulate records across all responses, then stitch them together.
    ptrs: dict[str, list[str]] = {st: [] for st in service_types}
    srvs: dict[str, tuple[str, int]] = {}
    txts: dict[str, dict[str, str]] = {}
    addrs: dict[str, str] = {}

    deadline = time.time() + timeout
    resent = False
    while time.time() < deadline:
        if not resent and time.time() > deadline - timeout / 2:
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))  # one retransmit
            resent = True
        try:
            data, _ = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        for name, rtype, rdata, off in _parse_records(data):
            if rtype == _PTR:
                target, _ = _decode_name(data, off)
                for st in service_types:
                    if name == st and target not in ptrs[st]:
                        ptrs[st].append(target)
            elif rtype == _SRV and len(rdata) >= 6:
                _prio, _weight, port = struct.unpack(">HHH", rdata[:6])
                host, _ = _decode_name(data, off + 6)
                srvs[name] = (host, port)
            elif rtype == _TXT:
                txts[name] = _parse_txt(rdata)
            elif rtype == _A and len(rdata) == 4:
                addrs[name] = socket.inet_ntoa(rdata)

    sock.close()

    services: list[HelmService] = []
    for st, instances in ptrs.items():
        for inst in instances:
            svc = HelmService(instance=inst, service_type=st.replace(".local", ""))
            if inst in srvs:
                svc.host, svc.port = srvs[inst]
                svc.address = addrs.get(svc.host, "")
            svc.txt = txts.get(inst, {})
            if not svc.address and svc.host:
                svc.address = _resolve(svc.host)
            services.append(svc)
    return services


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def _browse_zeroconf(service_types: list[str], timeout: float) -> list[HelmService]:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf  # type: ignore

    found: dict[str, HelmService] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=int(timeout * 1000))
            if not info:
                return
            addr = info.parsed_addresses()[0] if info.parsed_addresses() else ""
            txt = {
                k.decode("utf-8", "replace"): (v or b"").decode("utf-8", "replace")
                for k, v in (info.properties or {}).items()
            }
            found[name] = HelmService(
                instance=name.rstrip("."),
                service_type=type_.rstrip(".").replace(".local", ""),
                host=(info.server or "").rstrip("."),
                address=addr,
                port=info.port or 0,
                txt=txt,
            )

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf()
    listener = _Listener()
    browsers = [ServiceBrowser(zc, st + ".", listener) for st in service_types]
    try:
        time.sleep(timeout)
    finally:
        for _ in browsers:
            pass
        zc.close()
    return list(found.values())


if __name__ == "__main__":
    import sys

    all_types = "--all" in sys.argv
    types = GARMIN_SERVICE_TYPES if all_types else [HELM_SERVICE]
    print(f"Browsing for {', '.join(types)} ... (~4s)")
    results = browse(types, timeout=5.0)
    if not results:
        print("No Garmin services found. Are you on the plotter's WiFi network?")
        sys.exit(1)
    for s in results:
        print(f"  {s}")
        hint = s.rtsp_hint
        if hint:
            print(f"      rtsp hint: {hint}")
