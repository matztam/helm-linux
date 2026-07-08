"""Standalone input tester — verify mpv mouse->touch bridge WITHOUT the plotter.

Opens an empty mpv window and prints every touch event the bridge emits. Drag
around inside the window and watch the terminal:

  * a click should print  down ... up  at ~one position
  * a click-and-drag should print  down, then many move lines with CHANGING
    nx/ny, then up

If the move lines don't appear, motion events aren't firing. If they appear but
nx/ny never change, mpv isn't updating mouse-pos during the drag (a Wayland VO
issue) — tell me and I'll switch approaches.

    python3 -m helm.inputtest
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time


def main() -> int:
    lua = os.path.join(os.path.dirname(__file__), "mpv_input.lua")
    sock = os.path.join(tempfile.gettempdir(), f"helm-inputtest-{os.getpid()}.sock")
    if os.path.exists(sock):
        os.remove(sock)
    cmd = [
        "mpv", "--force-window=yes", "--idle=yes", "--keep-open=yes",
        "--osc=no", "--cursor-autohide=no", "--window-dragging=no",
        "--geometry=960x540", "--title=Helm input test — drag in here",
        f"--input-ipc-server={sock}", f"--script={lua}",
        # a visible test pattern so you can see where you're dragging
        "av://lavfi:color=c=0x203040:s=1280x720",
    ]
    print("launching mpv test window… drag inside it; Ctrl-C to stop.")
    proc = subprocess.Popen(cmd)

    s = None
    for _ in range(100):
        if os.path.exists(sock):
            try:
                s = socket.socket(socket.AF_UNIX); s.connect(sock); break
            except OSError:
                s = None
        time.sleep(0.1)
    if not s:
        print("could not connect to mpv IPC"); proc.terminate(); return 1

    s.settimeout(0.5)
    buf = b""
    n_down = n_move = n_up = 0
    last = None
    try:
        while proc.poll() is None:
            try:
                data = s.recv(8192)
            except socket.timeout:
                continue
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                if m.get("event") != "client-message":
                    continue
                a = m.get("args", [])
                if len(a) == 4 and a[0] == "helm_touch":
                    state, nx, ny = a[1], float(a[2]), float(a[3])
                    if state == "down":
                        n_down += 1
                    elif state == "move":
                        n_move += 1
                    elif state == "up":
                        n_up += 1
                    moved = "" if last is None else f"  Δ=({nx-last[0]:+.3f},{ny-last[1]:+.3f})"
                    print(f"  {state:4}  nx={nx:.3f} ny={ny:.3f}{moved}")
                    last = (nx, ny)
                elif len(a) == 4 and a[0] == "helm_scroll":
                    print(f"  SCROLL {a[1]:4}  nx={float(a[2]):.3f} ny={float(a[3]):.3f}"
                          f"  -> zoom {'in' if a[1]=='up' else 'out'}")
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
        if proc.poll() is None:
            proc.terminate()
        try:
            os.remove(sock)
        except OSError:
            pass
    print(f"\nsummary: down={n_down} move={n_move} up={n_up}")
    if n_move == 0:
        print("=> NO move events fired — motion isn't reaching the bridge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
