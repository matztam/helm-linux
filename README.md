# garmin-helm-linux

A Linux client for the **Helm** feature of Garmin ActiveCaptain — live-view and
**control your Garmin chartplotter's screen from a Linux laptop** over Wi‑Fi,
without the phone app.

Reverse-engineered from the ActiveCaptain app and verified against a **GPSMAP
923xsv**. See [PROTOCOL.md](PROTOCOL.md) for the wire protocol.

> Not affiliated with or endorsed by Garmin. For use with your own hardware on
> your own network.

## What works

- **Discovery** of the plotter over mDNS.
- **Pairing** — registers this machine as an ActiveCaptain user on the plotter.
- **Live video** — the chartplotter screen as RTSP/H.264.
- **Touch control** — click = tap, click‑and‑drag = pan, over the real session
  protocol (verified byte-for-byte against a capture).

Hardware keys (zoom/menu buttons) aren't implemented — a touchscreen unit is
fully controllable by touch; see [PROTOCOL.md](PROTOCOL.md) for how to add them.

## Requirements

- Python 3.10+ (standard library only — no pip packages required)
- **mpv** (recommended; required for the GUI's touch input). `ffplay` or `vlc`
  also work for view-only.
- Optionally `zeroconf` for more robust discovery on busy networks.

## Usage

Join the chartplotter's Wi‑Fi network, then:

```bash
# 1. one-time: register this machine with the plotter
python3 helm-cli.py pair
#    -> the plotter shows "a new ActiveCaptain user was added"
#    On the plotter, set App permissions to "View and Control"
#    (Settings -> Communications -> Wi-Fi Network -> Wi-Fi Devices)

# 2. live screen + touch control
python3 helm-gui.py
#    A small control panel opens plus an mpv video window.
#    Interact with the VIDEO window: click = tap, click-and-drag = pan.
```

Headless / view-only:

```bash
python3 helm-cli.py discover        # find the plotter
python3 helm-cli.py helm            # open the session and play the video
python3 helm-cli.py helm --no-video # session only (prints status/stream URL)
```

## Commands

| Command | Description |
|---|---|
| `helm-cli.py discover [--all]` | find Helm devices (or all Garmin services) |
| `helm-cli.py pair [--role guest\|owner] [--reset]` | register this machine |
| `helm-cli.py helm [--host IP] [--tap X Y]` | open session + play video |
| `helm-cli.py view <url>` | play any RTSP/MJPEG stream |
| `helm-cli.py analyze <pcap>` | decode a captured Helm session |
| `helm-gui.py` | GUI: video window + touch control |

## How it fits together

```
mDNS discover ─▶ pair (HTTP :80, bl-id register) ─▶ Helm session (TCP :51200)
                                                     ├─ handshake + touch input
                                                     └─ RTSP URL ─▶ video (:554)
```

- `helm/discovery.py` — mDNS browser
- `helm/credential.py` — pairing (bl-id registration)
- `helm/helm_client.py` — the `:51200` session: framing, handshake, touch
- `helm/video.py` + `helm/mpv_input.lua` — RTSP playback and the mpv→touch bridge
- `helm/analyze.py` — decode a session pcap (for extending the protocol)
- `helm/inputtest.py` — test the mouse→touch bridge without a plotter
- `helm/keys.py` — reverse-engineered key enum (reference; not wired up)

## Notes

- Touch input in the GUI is bridged from the mpv window over its IPC socket, so
  it works on Wayland and X11 without embedding. mpv runs with
  `--window-dragging=no` so click‑drag pans instead of moving the window.
- The plotter's RTSP server is UDP-only; the players are configured accordingly.

## License

MIT — see [LICENSE](LICENSE).
