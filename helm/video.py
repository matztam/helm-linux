"""Play the chartplotter's video stream (standard RTSP/H.264).

The stream is standard, so we don't reimplement any codec: we hand the URL to a
system player (mpv preferred, then ffplay, then vlc), forcing UDP transport
(Garmin's RTSP server rejects TCP-interleaved). ``play_with_input`` launches mpv
as the GUI's touch surface (see mpv_input.lua).
"""

from __future__ import annotations

import os
import shutil
import subprocess

# Low-latency flags: disable buffering/caching so control feels responsive.
# Garmin's RTSP server only supports UDP transport (RTP/AVP/UDP); requesting
# TCP-interleaved gets "461 Unsupported transport".
_MPV_LOWLAT = [
    "--profile=low-latency",
    "--no-cache",
    "--untimed",
    "--no-correct-pts",
    "--rtsp-transport=udp",
    "--hwdec=auto-safe",
]
_FFPLAY_LOWLAT = [
    "-fflags", "nobuffer",
    "-flags", "low_delay",
    "-rtsp_transport", "udp",
    "-framedrop",
]


def _player() -> str | None:
    for p in ("mpv", "ffplay", "vlc"):
        if shutil.which(p):
            return p
    return None


def build_command(url: str, player: str | None = None,
                  title: str = "Garmin Helm") -> list[str]:
    """Build the player command line for ``url`` (raises if no player found)."""
    player = player or _player()
    if not player:
        raise RuntimeError(
            "No video player found. Install one of: mpv, ffmpeg (ffplay), vlc.")
    if player == "mpv":
        return ["mpv", *_MPV_LOWLAT, f"--title={title}", "--force-window=yes", url]
    if player == "ffplay":
        return ["ffplay", *_FFPLAY_LOWLAT, "-window_title", title, url]
    if player == "vlc":
        return ["vlc", "--intf", "dummy", "--network-caching=100", url]
    raise RuntimeError(f"Unknown player: {player}")


def play(url: str, player: str | None = None, title: str = "Garmin Helm") -> int:
    """Play ``url`` in a standalone window, blocking until the player exits."""
    cmd = build_command(url, player=player, title=title)
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd)


def play_supervised(url: str, player: str | None = None,
                    title: str = "Garmin Helm") -> int:
    """Play ``url``, relaunching the player if it crashes (non-zero exit).
    A clean quit (exit 0) or Ctrl-C stops. Returns the last exit code."""
    import time
    backoff = 0.5
    while True:
        started = time.monotonic()
        try:
            rc = play(url, player=player, title=title)
        except KeyboardInterrupt:
            return 0
        if rc == 0:
            return 0
        backoff = 0.5 if time.monotonic() - started > 8 else min(backoff * 2, 5.0)
        print(f"player exited ({rc}); restarting in {backoff:.0f}s… (Ctrl-C to stop)")
        try:
            time.sleep(backoff)
        except KeyboardInterrupt:
            return 0


def play_with_input(url: str, ipc_path: str, title: str = "Garmin Helm") -> subprocess.Popen:
    """Launch mpv as the video + touch surface: it serves a JSON IPC socket at
    ``ipc_path`` and loads mpv_input.lua, which reports mouse events over it.
    Requires mpv. Runs native Wayland/X11; --window-dragging=no keeps click-drag
    as pointer input instead of moving the window (which broke drags on Wayland)."""
    if not shutil.which("mpv"):
        raise RuntimeError("mpv is required for the interactive GUI (touch via "
                           "the video window). Install mpv.")
    lua = os.path.join(os.path.dirname(__file__), "mpv_input.lua")
    cmd = ["mpv", *_MPV_LOWLAT, f"--title={title}", "--force-window=yes",
           "--keep-open=no", "--osc=no", "--cursor-autohide=no",
           "--window-dragging=no",
           f"--input-ipc-server={ipc_path}", f"--script={lua}", url]
    return subprocess.Popen(cmd)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m helm.video <rtsp-or-mjpeg-url>")
        raise SystemExit(2)
    raise SystemExit(play(sys.argv[1]))
