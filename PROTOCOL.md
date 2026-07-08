# Garmin ActiveCaptain "Helm" — protocol notes

Reverse-engineered from the ActiveCaptain Android app and verified against a
**GPSMAP 923xsv**. This documents the wire protocol the tool implements. It was
recovered by static analysis of the app's native core (`libgmm.so`) plus one
packet capture of a live Helm session.

Three independent channels, all over the plotter's own Wi‑Fi (default gateway
`172.16.6.0`):

| Channel | Transport | Purpose |
|---|---|---|
| Discovery | mDNS | find the plotter and its services |
| Pairing | HTTP (port 80) | register this device as an allowed user |
| Helm session | TCP `:51200` | device info, video URL, touch input |
| Video | RTSP/RTP `:554` | H.264 screen stream |

## 1. Discovery (mDNS)

The plotter advertises several `_garmin-*._tcp` services. The relevant ones:

- `_garmin-helm._tcp` (port **51200**, TXT `version`) — the Helm session.
- `_garmin-bl-id._tcp` (port **80**, TXT `tag`, `hasDisplay`, `version`) — the
  on-board HTTP identity server used for pairing.

Implemented in `helm/discovery.py` (pure-Python mDNS, no dependencies).

## 2. Pairing (HTTP, port 80)

The plotter's on-board HTTP server (nginx) authorizes clients by "bl-id"
(BlueLink id) registration:

1. **Register:** `PUT /garmin/bl-ids/<tag>` with body = protobuf
   `CSM.Proto.Common.MobileDeviceIdentity`:
   ```proto
   required string device_identifier   = 1;   // a UUID
   required uint32 client_generated_token = 2; // a random nonce
   optional string device_name         = 3;   // shown on the plotter screen
   ```
   `Content-Type: application/octet-stream`. The `<tag>` in the URL is
   `base64(client_generated_token[4 bytes little-endian] + 0x02 0x01 0x00 0x00)`
   with `=` padding stripped. Response is **202**, and the plotter displays
   *"a new ActiveCaptain user was added"*.
2. **Set role:** `PUT /garmin/bl-ids/<tag>/set-role` with JSON
   `{"role": "guest"|"owner"|"dealer"}`.
3. **Permission (manual):** on the plotter, set the **global** App-permission to
   **View and Control** (Settings → Communications → Wi‑Fi Network → Wi‑Fi
   Devices). This is a single global setting, not per-user.

There is no separate token to fetch — the Helm session is authorized by the
registering client's identity/address. (`/garmin/credentials/` is Wi‑Fi network
credentials, unrelated. `/Authentication/generate-token` is a cloud/account path
not used for the direct-to-plotter case.)

Implemented in `helm/credential.py`. Identity is persisted in
`helm-identity.json` and reused.

## 3. Helm session (TCP :51200)

Binary message framing:

```
[u16 type LE][u16 0xBEEF][u32 length LE][payload]
```

`0xBEEF` is a constant marker (`helm/helm_client.py:parse_frames`).

### Handshake (client → plotter)

| type | payload | meaning |
|---|---|---|
| `0x083f` | `0x9531` (u16) | hello / protocol tag |
| `0x0aa9` | 8 bytes | session token — client-chosen random |
| `0x1648` | u32 index | device select (`0x0b`) + data subscriptions |
| `0x1644` | *(empty)* | request a touch context |

The plotter replies `0x1645` = `[u32 1][u32 ctx_id]`. **`ctx_id` must be used as
the first 4 bytes of every touch message** — it is assigned by the plotter, not
chosen by the client.

### Plotter → client

`0x1649` events wrap `[u32 subtype][u32 length][data]`: subtype 0 = the RTSP
stream URL, subtype 1 = inline H.264, plus the device name (`"GPSMAP 923"`).

### Touch input (client → plotter), type `0x164c`

```
[u32 ctx_id][u32 count][ point × count ]
point = [u8 track_id][u32 x][u32 y][u32 down][pad×3]   (16 bytes)
```

`ctx_id` is the context the plotter assigned (`0x1645`). `x`, `y` are normalized
screen coordinates in 16.16 fixed point (`round(norm * 65536)`), from the
top-left. `down`: 1 = press/move, 0 = release. A single-finger message is
`count=1`, `track_id=0` (24 bytes). A drag is `down` … moving `down` … final
`up`.

**Multi-touch (confirmed from a pinch capture):** a two-finger message is
`count=2` with this exact 40-byte layout (fingers `track_id` 0 and 1):

```
[ctx:4][count=2:4] 00 [x0:4][y0:4][down0:1] 01 00 00 00 [x1:4][y1:4][down1:1] 00×9
```

`HelmClient.zoom` uses it (`encode_pinch`): two fingers move apart (zoom in) /
together (zoom out), centered on the cursor, mapped to the scroll wheel. Each
`x`/`y` is the same 16.16 normalized fixed point as single touch.

Hardware **keys** were not in the capture, so their message format is unknown;
the key enum is preserved in `helm/keys.py` for future work. A touchscreen unit
is fully controllable by touch.

## 4. Video (RTSP, port 554)

`rtsp://<plotter-host>:554/helm_1280x720.h264` — standard RTSP; the SDP is
`m=video RTP/AVP 96`, `H264/90000`, `packetization-mode=1`. The server only
supports **UDP** transport (`RTP/AVP/UDP`); requesting TCP-interleaved returns
`461 Unsupported transport`. Any standard player works (`helm/video.py` uses
mpv/ffplay/vlc with `--rtsp-transport=udp`).

## Reproducing / extending

`helm/analyze.py` decodes a captured session pcap into the frames above
(`python3 -m helm.analyze helm.pcap --port 51200`) — useful for adding key
support or supporting other units. Capture the phone↔plotter traffic with
PCAPdroid (root mode, so mDNS works) or `tcpdump` where you can see it. Because
Wi‑Fi unicast can't be sniffed passively from another station, an on-path
capture (rooted phone, or ARP redirection on your own network) is required.

## Legal

Interoperability reverse engineering for use with your own hardware on your own
network. No Garmin code is included — only the observable protocol behavior is
reimplemented. Not affiliated with or endorsed by Garmin.
