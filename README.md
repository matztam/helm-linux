# garmin-helm-linux

A Linux alternative to the **Helm** feature of the Garmin ActiveCaptain phone
app — live-view and control your Garmin chartplotter screen from a Linux laptop
over WiFi.

Built by reverse-engineering the ActiveCaptain APK. See **[PROTOCOL.md](PROTOCOL.md)**
for how it works and what's confirmed vs. still needs a live capture.

## Status at a glance

| Feature | Works? | Notes |
|---|---|---|
| **Discover plotters** (mDNS) | ✅ | pure-Python, no deps |
| **Pair** this machine with the plotter | ✅ | `helm-cli.py pair` (registers a bl-id) |
| **View screen** (RTSP H.264) | ✅ | `rtsp://<host>:554/helm_1280x720.h264` via mpv |
| **Touch control** (click/drag) | ✅ | full 0xBEEF/0x164c session protocol, RE'd from capture |
| **Hardware keys** (zoom/menu buttons) | 🚧 | message type not yet captured; touchscreen units don't need it |

The whole path is reverse-engineered and implemented: mDNS discovery → bl-id
pairing (HTTP) → the `:51200` Helm session (`[type][0xBEEF][len][payload]`
framing, handshake, and `0x164c` touch messages) → RTSP/H.264 video. See
**[PROTOCOL.md](PROTOCOL.md)** and **[PAIRING.md](PAIRING.md)**.

### Quick start
```bash
python3 helm-cli.py pair      # one-time: register this machine (accept on plotter if prompted)
python3 helm-gui.py           # small control panel + a video window you touch
# or headless video only:
python3 helm-cli.py helm      # opens the session and plays the video
```
On the plotter, set the global **App permissions** to **View and Control**.

In the GUI, interact with the **video window**: click = tap, click-and-drag =
pan/swipe. (Requires **mpv**; input is bridged from the mpv window over its IPC
socket, so it works on Wayland and X11 without window embedding.)

## Requirements

* Python 3.10+ (standard library only for discovery/probe/control)
* A video player: **mpv** (recommended), or ffmpeg's ffplay, or vlc
* Optional: `zeroconf` (`pip install zeroconf`) for more robust discovery
* Optional: `tcpdump` + Wireshark to finalize the control channel

Everything here is self-contained; no build step.

## Usage

Join the plotter's WiFi first (the network the chartplotter broadcasts, or a
shared boat network).

```bash
# 1. Find your plotter
python3 helm-cli.py discover
#   -> GPSMAP 1243xsv   address: 192.168.1.50:9000   rtsp: rtsp://192.168.1.50:554/...

# See every Garmin service on the network
python3 helm-cli.py discover --all

# 2. Inspect the video stream (confirm codec / exact URL)
python3 helm-cli.py probe rtsp://192.168.1.50:554/helm

# 3. Watch the screen
python3 helm-cli.py view rtsp://192.168.1.50:554/helm

# 4. Full GUI: live video + on-screen keys + click-to-touch
python3 helm-gui.py --host 192.168.1.50 --url rtsp://192.168.1.50:554/helm
#   (or just run it and click "Discover")
```

### GUI controls
* Click/drag on the video = touch/drag on the plotter.
* On-screen buttons and keyboard shortcuts send Helm keys:
  arrows = pan, `+`/`-` = zoom, Enter = select, Esc/Backspace = back,
  `m` = menu, `h` = home, `k` = mark.

## Finalizing key/touch control

The keys/touches are modeled correctly (`helm/keys.py`), but the byte framing of
Garmin's VCM control bus needs one observation from a real device:

```bash
# with the phone app actively controlling the plotter:
python3 -m helm.capture --host 192.168.1.50
#   -> writes helm.pcap; open in Wireshark, find the input stream
```

Then implement the observed framing in a `Transport` subclass in
`helm/control.py` (the default `CaptureNeededTransport` explains exactly what to
look for). Full walkthrough in [PROTOCOL.md](PROTOCOL.md) §4.

## Project layout

```
helm-cli.py          CLI: discover / probe / view / key / tap / capture
helm-gui.py          tkinter GUI: video + keypad + touch
helm/
  discovery.py       mDNS browse for _garmin-helm._tcp (pure Python)
  video.py           RTSP/MJPEG playback via mpv/ffplay/vlc
  keys.py            HelmKey enum + HelmTouch model (from the app)
  control.py         RTSP probe + pluggable control transport
  capture.py         traffic-capture helper to finalize control
PROTOCOL.md          reverse-engineering write-up
```

## Legal

For interoperability with your own hardware on your own network. No Garmin code
is included; only observable protocol behavior is reimplemented.
