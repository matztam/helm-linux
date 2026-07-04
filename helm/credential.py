"""Pairing: register this machine with the plotter.

The plotter runs an on-board HTTP server (advertised as _garmin-bl-id._tcp on
port 80). Pairing is:

  1. Discover the service (its TXT `tag` decodes to bytes; the last one is a
     user-generation counter).
  2. PUT /garmin/bl-ids/<tag> with a protobuf MobileDeviceIdentity
     {device_identifier, client_generated_token, device_name}. <tag> =
     base64(client_generated_token[4B LE] + 02 01 00 00). The plotter returns
     202 and shows "a new ActiveCaptain user was added" on screen.
  3. PUT /garmin/bl-ids/<tag>/set-role  JSON {"role": "guest"|"owner"|"dealer"}.
  4. On the plotter, set the global App-permission to "View and Control".

The identity is persisted (helm-identity.json) and reused so we don't create a
new user every run. Once paired, connect with helm.helm_client (the Helm
session on :51200 is authorized by our registered identity — no token needed).
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
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
    """Find the plotter's on-board HTTP identity service.

    Advertised as _garmin-bl-id._tcp (port 80; TXT: tag, hasDisplay, version),
    which hosts /garmin/bl-ids/ used for pairing. (_garmin-mrn-cred._tcp is the
    same service on some units.)
    """
    svcs = discovery.browse(
        [discovery.CRED_SERVICE, "_garmin-bl-id._tcp.local"], timeout=timeout
    )
    svcs.sort(key=lambda s: 0 if "cred" in s.service_type else 1)
    return svcs[0] if svcs else None


class CredentialClient:
    """HTTP client for the plotter's on-board identity service (bl-ids)."""

    def __init__(self, host: str, port: int, timeout: float = 8.0):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _request(self, method: str, path: str, body=None, headers=None):
        hdrs = {"Accept": "application/json", "User-Agent": "garmin-helm-linux"}
        data = bytes(body) if isinstance(body, (bytes, bytearray)) else None
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self.base + path, data=data,
                                     method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except urllib.error.URLError as e:
            return None, {}, str(e).encode()

    def register_blid(self, ident: dict):
        """PUT /garmin/bl-ids/<tag> with a protobuf MobileDeviceIdentity.
        Returns 202; the plotter shows "a new ActiveCaptain user was added"."""
        body = encode_mobile_device_identity(
            ident["device_identifier"], ident["client_generated_token"],
            ident["device_name"])
        return self._request(
            "PUT", f"/garmin/bl-ids/{ident['tag']}", body,
            headers={"Content-Type": "application/octet-stream"})

    def set_role(self, tag: str, role: str = "guest"):
        """PUT /garmin/bl-ids/<tag>/set-role  JSON {"role": ...}."""
        body = json.dumps({"role": role}).encode()
        return self._request("PUT", f"/garmin/bl-ids/{tag}/set-role", body,
                             headers={"Content-Type": "application/json"})


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return raw


def _resolve(host, port):
    if host:
        return host, port or 80
    svc = discover_credential_service()
    if not svc:
        print("No bl-id service found. Are you on the plotter's Wi-Fi?")
        return None, None
    print(f"Identity service: {svc}")
    return (svc.address or svc.host), (port or svc.port or 80)


def probe(host: str | None, port: int | None, role: str = "guest") -> int:
    """Register this machine with the plotter (once, reused) and request a role.

    After this succeeds, set the plotter's global App-permission to
    "View and Control" and connect with `helm` / the GUI.
    """
    host, port = _resolve(host, port)
    if not host:
        return 1
    client = CredentialClient(host, port)

    ident = load_identity()
    if ident:
        print(f"Reusing saved identity: name={ident['device_name']!r} tag={ident['tag']}")
    else:
        ident = make_identity("Linux Helm")
        print(f"Registering '{ident['device_name']}' (tag {ident['tag']}) "
              "— watch the plotter screen…")
        st, _, _ = client.register_blid(ident)
        if not (st and st < 300):
            print(f"  registration failed (HTTP {st}).")
            return 1
        save_identity(ident)
        print(f"  registered (HTTP {st}); saved -> {STATE_FILE}")

    st, _, _ = client.set_role(ident["tag"], role)
    print(f"set-role {role!r}: HTTP {st}")
    print("\nDone. On the plotter set App permissions to 'View and Control', "
          "then run:\n  python3 helm-cli.py helm      (or: python3 helm-gui.py)")
    return 0


def list_users(host: str | None, port: int | None) -> int:
    """The user list isn't exposed to clients over HTTP; point at the plotter."""
    print("Registered users aren't listed over HTTP by the plotter.\n"
          "View/manage paired users on the plotter screen:\n"
          "  Settings → Communications → Wi-Fi Network → Wi-Fi Devices")
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
