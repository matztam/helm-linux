"""Pairing + credential acquisition for the Helm/VCM control channel.

WHAT GATES HELM
---------------
Connecting to the plotter's GMN 2.0 control channel is authorized by a **VCM
auth JWT** (native: msl/vcm/Auth/SeedJwt.cpp, "Cannot seed VCM auth JWT"). That
JWT is presented as `Authorization: Bearer <token>`. To obtain it standalone we
reproduce what the app does when connected directly to the plotter (no
internet):

  1. Discover the plotter's **credential service**: mDNS `_garmin-mrn-cred._tcp`
     (TXT carries `tag` + `version`).
  2. **Pair**: send a BCM network pair request; the plotter shows a confirm /
     pass-key prompt on its screen; the user confirms (CONFIRMED / REJECTED /
     NO_ACTION). This authorizes this client as a known device.
  3. **Get a token**: POST to the credential service
     `/Authentication/generate-token` with the device identity; the plotter
     returns JSON `{"credentials","device_id","role","token","expires"}` where
     `token` is the JWT.  (`/Authentication/refresh-token` renews it; note the
     app also has a *cloud* issuer at profile*.marine.garmin.com for the
     internet path -- we use the on-plotter local issuer.)
  4. Use that JWT as Bearer on the GMN 2.0 / RTSP session (helm.gmn2 / helm.video).

STATUS: the HTTP/JSON parts (steps 1, 3, 4) are implemented from the
reverse-engineered field names and are directly testable against the plotter.
The BCM pair request (step 2) is a binary-serialized message
(`bcm_pair_request_serialize`) whose exact layout still needs confirming -- the
plotter's own error responses when you hit generate-token unpaired will tell us
what it expects, which is why the probe below is the right next step.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import discovery

# Persist our registered identity so we reuse ONE bl-id instead of creating a
# new "ActiveCaptain user" on the plotter every run.
STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "helm-identity.json")


def load_identity() -> dict | None:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_identity(ident: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(ident, f, indent=2)


def make_identity(name: str = "Linux Helm") -> dict:
    """Create a fresh bl-id identity. tag = base64(token[4 LE] + 02 01 00 00)."""
    token = uuid.uuid4().int & 0xFFFFFFFF
    tag_bytes = token.to_bytes(4, "little") + bytes([0x02, 0x01, 0x00, 0x00])
    tag = base64.b64encode(tag_bytes).decode().rstrip("=")
    return {
        "device_identifier": str(uuid.uuid4()),
        "client_generated_token": token,
        "device_name": name,
        "tag": tag,
    }

# Fields the app sends when requesting a token (from libgmm.so):
#   client_id, device_id, unit_id, role, clientTime  -> returns {token/jwtToken}
DEFAULT_ROLE = "helm"

# VCM roles (VesselConnectManager.RoleType ordinals)
VCM_ROLE_NONE, VCM_ROLE_OWNER, VCM_ROLE_GUEST, VCM_ROLE_DEALER = 0, 1, 2, 3


# --- minimal protobuf wire encoding (no runtime dependency) ---------------
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _pb_string(field: int, s: str) -> bytes:
    b = s.encode("utf-8")
    return bytes([field << 3 | 2]) + _varint(len(b)) + b


def _pb_uint32(field: int, n: int) -> bytes:
    return bytes([field << 3 | 0]) + _varint(n)


def encode_mobile_device_identity(device_identifier: str,
                                  client_generated_token: int,
                                  device_name: str) -> bytes:
    """CSM.Proto.Common.MobileDeviceIdentity:
       required string device_identifier=1; required uint32 client_generated_token=2;
       optional string device_name=3."""
    return (_pb_string(1, device_identifier)
            + _pb_uint32(2, client_generated_token & 0xFFFFFFFF)
            + _pb_string(3, device_name))


def discover_credential_service(timeout: float = 5.0):
    """Find the plotter's HTTP identity/credential service.

    Prefers _garmin-mrn-cred._tcp, but real units advertise the same on-board
    HTTP server (port 80) as _garmin-bl-id._tcp (TXT: tag, hasDisplay, version).
    That port-80 server hosts /garmin/bl-ids/, /garmin/credentials/ and
    /Authentication/generate-token.
    """
    svcs = discovery.browse(
        [discovery.CRED_SERVICE, "_garmin-bl-id._tcp.local"], timeout=timeout
    )
    # prefer an explicit credential service, else the bl-id HTTP server
    svcs.sort(key=lambda s: 0 if "cred" in s.service_type else 1)
    return svcs[0] if svcs else None


# Endpoints on the plotter's port-80 server (from libgmm.so), most useful first.
PROBE_PATHS = [
    ("GET", "/Garmin/GarminDevice.xml"),  # device identity: unit id, product no.
    ("GET", "/garmin/bl-ids/"),           # registered BlueLink identities
    ("GET", "/garmin/credentials/"),      # credential status
    ("GET", "/garmin/inventory/device/"),
    ("GET", "/device/"),
]


class CredentialClient:
    """HTTP client for the plotter's marine credential service."""

    def __init__(self, host: str, port: int, timeout: float = 8.0):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _request(self, method: str, path: str, body=None, headers=None):
        url = self.base + path
        data = None
        hdrs = {"Accept": "application/json", "User-Agent": "garmin-helm-linux"}
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, dict(resp.headers), raw
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except urllib.error.URLError as e:
            return None, {}, str(e).encode()

    def status(self):
        """GET /garmin/credentials/  -- credential status probe."""
        return self._request("GET", "/garmin/credentials/")

    def register_blid(self, ident: dict):
        """PUT /garmin/bl-ids/<tag> with protobuf MobileDeviceIdentity.

        CONFIRMED working: returns 202 and the plotter shows "a new ActiveCaptain
        user was added". Returns (status, headers, body).
        """
        body = encode_mobile_device_identity(
            ident["device_identifier"], ident["client_generated_token"],
            ident["device_name"])
        return self._request(
            "PUT", f"/garmin/bl-ids/{ident['tag']}", body,
            headers={"Content-Type": "application/octet-stream"},
        )

    def get_blid(self, tag: str, accept: str = "application/json"):
        """GET /garmin/bl-ids/<tag> — our registration record (role/status)."""
        return self._request("GET", f"/garmin/bl-ids/{tag}",
                             headers={"Accept": accept})

    def set_role(self, tag: str, role: str = "guest"):
        """set-role — JSON {"role": "guest"|"owner"}. Identity via the bl-id
        tag in the URL (falls back to /garmin/bl-ids/set-role)."""
        body = json.dumps({"role": role}).encode()
        hdrs = {"Content-Type": "application/json"}
        # try the per-bl-id path first, then the flat endpoint
        for method, path in (("PUT", f"/garmin/bl-ids/{tag}/set-role"),
                             ("POST", f"/garmin/bl-ids/{tag}/set-role"),
                             ("PUT", "/garmin/bl-ids/set-role"),
                             ("POST", "/garmin/bl-ids/set-role")):
            st, h, raw = self._request(method, path, body, headers=hdrs)
            if st and st != 404 and st != 405:
                return method, path, st, h, raw
        return None, None, st, h, raw

    def get_credentials(self, tag: str):
        """GET the credential/token record for our bl-id."""
        for path in (f"/garmin/bl-ids/{tag}/credentials",
                     f"/garmin/credentials/{tag}", "/garmin/credentials/"):
            st, h, raw = self._request("GET", path,
                                       headers={"Accept": "application/json"})
            if st and st != 404:
                return path, st, h, raw
        return None, st, h, raw

    def generate_token(self, device_id: str, unit_id: str,
                       client_id: str | None = None, role: str = DEFAULT_ROLE):
        """POST /Authentication/generate-token. Returns (status, headers, json|bytes)."""
        body = {
            "client_id": client_id or str(uuid.uuid4()),
            "device_id": device_id,
            "unit_id": unit_id,
            "role": role,
            "clientTime": str(int(time.time())),
        }
        st, hdrs, raw = self._request("POST", "/Authentication/generate-token", body)
        return st, hdrs, _maybe_json(raw)

    def refresh_token(self, token: str):
        st, hdrs, raw = self._request(
            "POST", "/Authentication/refresh-token",
            {"token": token, "clientTime": str(int(time.time()))},
        )
        return st, hdrs, _maybe_json(raw)


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw


def _stable_device_id() -> str:
    """A stable pseudo-unit-id for this laptop (48-bit like a Garmin unit id)."""
    return str(uuid.getnode())


def _show(label, st, hdrs, raw):
    b = bytes(raw) if isinstance(raw, (bytes, bytearray)) else raw
    ct = hdrs.get("Content-Type", "") if hdrs else ""
    print(f"[{label}] -> HTTP {st}  {ct}")
    if isinstance(b, bytes):
        j = _maybe_json(b)
        print(f"    {j if isinstance(j, dict) else b[:220]!r}"
              + (f"  hex:{b[:48].hex()}" if b and not isinstance(j, dict) else ""))
    else:
        print(f"    {b!r}"[:300])
    return _maybe_json(b) if isinstance(b, bytes) else b


def probe(host: str | None, port: int | None, role: str = "guest") -> int:
    """Staged, persistent pairing flow against the plotter's bl-id service.

    register (once, reused) -> read our record -> set-role -> get credentials.
    """
    if not host:
        svc = discover_credential_service()
        if not svc:
            print("No credential/bl-id service found. On the plotter's WiFi?")
            return 1
        print(f"Identity service: {svc}")
        host = svc.address or svc.host
        port = port or svc.port
    client = CredentialClient(host, port or 80)

    # Reuse a saved identity if we have one; else register a fresh one.
    ident = load_identity()
    if ident:
        print(f"Reusing saved identity: name={ident['device_name']!r} "
              f"tag={ident['tag']}")
    else:
        ident = make_identity("Linux Helm")
        print(f"Registering NEW identity: name={ident['device_name']!r} "
              f"tag={ident['tag']}  <-- WATCH PLOTTER SCREEN")
        st, hdrs, raw = client.register_blid(ident)
        _show(f"PUT /garmin/bl-ids/{ident['tag']}", st, hdrs, raw)
        if st and st < 300:
            save_identity(ident)
            print(f"    saved identity -> {STATE_FILE}")
        else:
            print("    registration failed; not saving. Share output.")
            return 1

    tag = ident["tag"]
    print()
    # 1) our registration record (role / status)
    st, hdrs, raw = client.get_blid(tag)
    rec = _show(f"GET /garmin/bl-ids/{tag}", st, hdrs, raw)

    # 2) request a role (guest is usually enough for Helm view/control)
    print(f"\nRequesting role {role!r} ...")
    method, path, st, hdrs, raw = client.set_role(tag, role)
    _show(f"{method} {path}" if method else "set-role (all variants 404/405)",
          st, hdrs, raw)

    # 3) fetch the credential/token (required keys: tag, credentials)
    print()
    path, st, hdrs, raw = client.get_credentials(tag)
    cred = _show(f"GET {path}" if path else "credentials (not found)",
                 st, hdrs, raw)
    if isinstance(cred, dict) and cred.get("credentials"):
        print("\n  >>> GOT CREDENTIALS. This is the auth material for the "
              "GMN2/Helm session.")
        ident["credentials"] = cred
        save_identity(ident)
    else:
        print("\n  Registered OK. Share the GET/set-role/credentials output "
              "above so we\n  wire the token into the GMN2 Helm connection next.")
    return 0


def list_users(host: str | None, port: int | None) -> int:
    """Best-effort: ask the plotter for its registered bl-ids / users."""
    if not host:
        svc = discover_credential_service()
        if not svc:
            print("No bl-id service found. On the plotter's WiFi?")
            return 1
        host = svc.address or svc.host
        port = port or svc.port
    client = CredentialClient(host, port or 80)
    ident = load_identity()
    my_tag = ident["tag"] if ident else None
    # Try a few list-style requests (endpoint/params still being pinned down).
    tries = [
        ("GET", "/garmin/bl-ids/", {"Accept": "application/json"}),
        ("GET", "/garmin/bl-ids", {"Accept": "application/json"}),
        ("GET", "/garmin/inventory/device/", {"Accept": "application/json"}),
    ]
    if my_tag:
        tries.insert(0, ("GET", f"/garmin/bl-ids/?requester={my_tag}",
                         {"Accept": "application/json"}))
    for method, path, hdrs in tries:
        st, h, raw = client._request(method, path, headers=hdrs)
        _show(f"{method} {path}", st, h, raw)
    print("\n(If these 400, the user list isn't exposed over HTTP to clients — "
          "\n view paired users on the plotter screen: Communications → Wi-Fi.)")
    return 0


def reset_identity() -> int:
    try:
        os.remove(STATE_FILE)
        print(f"removed {STATE_FILE}")
    except OSError:
        print("no saved identity")
    return 0


if __name__ == "__main__":
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else None
    p = int(sys.argv[2]) if len(sys.argv) > 2 else None
    raise SystemExit(probe(h, p))
