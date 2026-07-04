# Garmin ActiveCaptain "Helm" — reverse-engineered protocol notes

These notes come from static analysis of the ActiveCaptain Android app
(`com.garmin.android.marine`, v36.0.2694): the decompiled Java (`classes.dex`
via jadx) and string/symbol analysis of the native core `libgmm.so` (81 MB,
"Garmin Mobile Marine"). No device traffic was captured. Anything marked
**(confirmed)** is directly evidenced; **(inferred)** is a best hypothesis to
validate against a real plotter.

## Architecture overview

The whole Helm stack is native (C/C++) in `libgmm.so`, under
`apprepo/lib/marine-mobile-core/`. The Java classes are thin JNI shims:

| Java class | Role |
|---|---|
| `com.garmin.android.gmm.HelmClientManager` | keys/touches, device/station enumeration |
| `com.garmin.android.gmm.RtspClient` | video stream client (native RTSP) |
| `com.garmin.android.gmm.OneHelmManager` | "OneHelm" web-app servers |
| `com.garmin.android.gmm.objects.HelmDevice` | one plotter: id, name, `streamUrl`, aspect ratio, rotation, `KeyConfig`, screenshot |
| `com.garmin.android.marine.helm.HelmStreamingActivity` | the on-phone screen: video + on-screen keys/touch |

Native subsystem doing the work: **VCM = "Vessel Connect Manager"**
(`msl/vcm/…`). Key files seen in embedded build paths:

```
msl/vcm/client/service-discovery/vcm_service_discovery.c   <- mDNS browse
msl/vcm/client/service-discovery/vcm_service_connection.c   <- TCP session setup
msl/vcm/client/helm/vcm_helm_state.c                        <- Helm state machine
msl/vcm/client/rest/vcm_http_client.c / vcm_rest_client.c   <- HTTP/JSON API
msl/vcm/Auth/*  (Jwt.cpp, JwtManager.cpp, RefreshJwt.cpp…)   <- JWT auth
gmm/RtspClient.cpp                                           <- video
msl/modules/rtp-payloads/h264/rtp_h264_depacketize.c        <- H.264 over RTP
```

## 1. Discovery — mDNS / Bonjour  **(confirmed)**

The app embeds Apple mDNSResponder and browses these service types:

```
_garmin-helm._tcp      <- Helm remote view/control  (the one we want)
_garmin-bl-app._tcp    <- BlueLink app messaging bus
_garmin-marine._udp    <- marine network announce
_garmin-mrn-html._tcp  <- on-device HTML/web UI ("OneHelm")
_garmin-swifi._tcp, _garmin-mrn-card._tcp, _garmin-mrn-cred._tcp, …
```

Native log format strings prove the record shape:

```
"Helm service added: %s %s:%d version: %d"   -> name, host/ip, port, protocol version
"Helm service address changed: %s %s"
"Helm service remove: %s"
```

So each Helm plotter advertises **name, host, IPv4, TCP port, and a version**
in its SRV/TXT records. → Implemented in `helm/discovery.py` (pure-Python mDNS,
no deps; falls back to `zeroconf` if installed).

## 2. Video — RTSP + RTP + H.264 (or MJPEG)  **(confirmed)**

`RtspClient` connects to `HelmDevice.getStreamUrl()`. Evidence it's standard
RTSP: strings `DESCRIBE`, `Accept: application/sdp`, `H264/90000`,
`h264-depacketize`, `All streams setup, starting play on client`,
`avc1`, `H.264`.

Two stream flavours:
* **H.264 over RTP/RTSP** — the default. `rtp_h264_depacketize.c` reassembles
  NAL units.
* **MJPEG** — some units. The app checks `if streamUrl contains "mjpg"` in
  `HelmStreamingActivity` to toggle the record-to-file menu item.

Both are decodable by any standard player. → `helm/video.py` shells out to
mpv/ffplay/vlc; `helm/control.py:RtspProbe` does a pure-Python OPTIONS+DESCRIBE
to fetch the SDP and confirm the codec / exact media URL.

**Open item:** where `streamUrl` comes from. It is a field on `HelmDevice`,
populated natively — most likely returned by the control session (step 3) or
derivable from the mDNS host + a fixed path. Capture (step 4) resolves this; in
the meantime you can pass any RTSP URL you observe directly to `view`.

## 3. Control — keys & touches  **(model confirmed, transport inferred)**

`HelmClientManager` native methods:

```java
nativeSendKeys(long deviceId, ArrayList<HelmKey> keys)
nativeSendTouches(long deviceId, ArrayList<HelmTouch> touches)
nativeSetActiveDevice(long deviceId)
nativeControlAllowed() / nativeViewAllowed()
```

### Keys — **confirmed model**
`HelmKey` is an ordinal enum (wire value = position). Full list in
`helm/keys.py`. Highlights: `HLM_KEY_ZOOM_IN=1`, `ZOOM_OUT=2`, `DIR_UP=3`,
`DIR_DOWN=4`, `DIR_LEFT=5`, `DIR_RIGHT=6`, `SELECT=7`, `BACK=8`, `MENU=9`,
`HOME=10`, `MARK=11`, soft keys 1–8 (12–19), numeric pad (20–31), knob
left/right/push (34–36), presets 1–4 (37–40).

A device reports its physical layout via `HelmDevice.KeyConfig`
(`HLM_KEY_CFG_NONE`=touch-only … `HLM_KEY_CFG_4`).

### Touches — **confirmed model**
`HelmClientManager.HelmTouch(trackId, float x, float y, boolean down)` stores
`x = (int)(x * 65536)`, `y = (int)(y * 65536)` — i.e. **normalized [0,1] screen
coordinates in 16.16 fixed point** (`TOUCH_UNITY = 65536`). `trackId` groups a
multi-touch gesture; `down` = press/move vs release.

### Transport — **inferred, needs capture**
This is the one unresolved piece. The keys/touches are dispatched through the
VCM app-bus after an **authenticated** session:

* Discovery gives a TCP `host:port` for `_garmin-helm._tcp`.
* `vcm_service_connection.c` opens a session; native log
  `"Cannot setup new client local app_id %d to %s:%u remote app_id %u"` shows an
  **app-id-addressed message bus** (Garmin BlueLink-style), not plain HTTP for
  input.
* Auth is **JWT** (`msl/vcm/Auth/*`: `GenerateJwt`, `RefreshJwt`, `SeedJwt`,
  `JwtMiddleware`). There is a REST/JSON layer (`vcm_rest_client.c`,
  `vcm_rest_json.c`) used for some VCM operations, and a JSON snippet
  `Return value is in JSON format: { "x": "200", "y": "300" }` suggests some
  coordinate calls are JSON — but the high-rate touch/key path is more likely a
  compact binary bus message.

The exact framing (message header, app-id values, whether keys/touches are JSON
over REST or binary bus frames, and the JWT/pairing handshake) is **not
recoverable from static strings** and must be observed on a live device.

## 4. Finalizing the control channel

1. Laptop + phone on the plotter's WiFi.
2. `python -m helm.capture --host <plotter-ip>` (or `sudo tcpdump -w helm.pcap
   host <plotter-ip>`).
3. In the app: open Helm, press keys, tap the screen.
4. In Wireshark, find the non-RTSP TCP stream that lights up on input. Identify:
   * the session/auth handshake (look for a JWT — a `eyJ…` base64 blob),
   * the per-key and per-touch frame layout (expect the fixed-point coords
     `x*65536`, `y*65536`, the `HelmKey` ordinal, and the `down` flag),
   * the port (the mDNS-advertised Helm port).
5. Encode that framing in a new `Transport` subclass in `helm/control.py`
   (replacing `CaptureNeededTransport`). The semantic layer (`HelmControlClient`,
   `HelmKey`, `HelmTouch`) is already correct, so only the byte-packing/handshake
   is left.

`helm/control.py` ships two starting points: `CaptureNeededTransport` (default —
prints the semantic payload and how to capture) and
`RtspSetParameterTransport` (an experimental "control over RTSP SET_PARAMETER"
hypothesis to try and confirm or discard).

## Legal / usage note
For your own device on your own network. This is interoperability reverse
engineering of a protocol Garmin does not publish; no Garmin code is reused —
only the observable protocol behavior is reimplemented.
