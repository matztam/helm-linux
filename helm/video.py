"""Play the chartplotter's video stream.

The Helm feature streams the plotter screen as either:
  * RTSP + RTP + H.264  (H264/90000 in the SDP) -- most units, or
  * MJPEG over HTTP      -- some units (stream URL contains "mjpg").

Both are standard, so we don't need to reimplement any codec: we hand the URL
to a system player (mpv preferred, then ffplay, then vlc). ``play_embedded``
renders into an existing X11 window id so the GUI can host the video.

The stream URL normally comes from HelmDevice.getStreamUrl() over the control
channel. Until the control channel is finalized, you can pass a URL you
discovered (from a capture, or a TXT record) directly.
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


def build_command(
    url: str,
    player: str | None = None,
    wid: int | None = None,
    title: str = "Garmin Helm",
    extra: list[str] | None = None,
) -> list[str]:
    """Build the player command line for ``url``.

    ``wid`` embeds the video into an existing window (X11 window id) when the
    player supports it (mpv, vlc). Raises RuntimeError if no player is found.
    """
    player = player or _player()
    if not player:
        raise RuntimeError(
            "No video player found. Install one of: mpv, ffmpeg (ffplay), vlc."
        )

    if player == "mpv":
        cmd = ["mpv", *_MPV_LOWLAT, f"--title={title}", "--force-window=yes"]
        if wid is not None:
            cmd.append(f"--wid={wid}")
        cmd += (extra or [])
        cmd.append(url)
        return cmd

    if player == "ffplay":
        cmd = ["ffplay", *_FFPLAY_LOWLAT, "-window_title", title]
        # ffplay cannot embed into an arbitrary window id.
        cmd += (extra or [])
        cmd.append(url)
        return cmd

    if player == "vlc":
        cmd = ["vlc", "--intf", "dummy", "--network-caching=100"]
        if wid is not None:
            cmd += ["--drawable-xid", str(wid)]
        cmd += (extra or [])
        cmd.append(url)
        return cmd

    raise RuntimeError(f"Unknown player: {player}")


def play(url: str, player: str | None = None, title: str = "Garmin Helm") -> int:
    """Play ``url`` in a standalone window, blocking until the player exits."""
    cmd = build_command(url, player=player, title=title)
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd)


def play_embedded(
    url: str, wid: int, player: str | None = None, title: str = "Garmin Helm"
) -> subprocess.Popen:
    """Launch a player embedded in X11 window ``wid``; returns the Popen handle."""
    player = player or _player()
    if player == "ffplay":
        player = "mpv" if shutil.which("mpv") else ("vlc" if shutil.which("vlc") else None)
        if not player:
            raise RuntimeError("Embedding needs mpv or vlc (ffplay can't embed).")
    cmd = build_command(url, player=player, wid=wid, title=title)
    return subprocess.Popen(cmd)


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
