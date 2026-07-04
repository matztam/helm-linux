#!/usr/bin/env python3
"""garmin-helm-linux GUI — live chartplotter view + touch control on Linux.

The plotter screen plays in an mpv window that doubles as the touch surface:
mpv loads a small Lua bridge (helm/mpv_input.lua) that reports mouse press /
drag / release over its JSON IPC socket; this GUI reads those and sends the
matching Helm touch frames over the :51200 session (helm.helm_client). A small
control panel handles connect / status.

This avoids window embedding, so it works on Wayland and X11 alike. Interact
with the *video window*: click to tap, click-and-drag to pan.

Prereqs (one-time): register this machine — `python3 helm-cli.py pair` on the
plotter's Wi-Fi — and set the plotter's global App-permission to
"View and Control". Requires mpv.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from helm import discovery, video
from helm.helm_client import HelmClient


class HelmGui:
    def __init__(self, root: tk.Tk, host: str | None):
        self.root = root
        self.host = host or ""
        self.client: HelmClient | None = None
        self.player = None
        self.ipc_path = os.path.join(tempfile.gettempdir(),
                                     f"helm-mpv-{os.getpid()}.sock")
        self._ipc_thread: threading.Thread | None = None
        self._running = False

        root.title("Garmin Helm — control")
        root.geometry("440x220")
        self._build()
        if self.host:
            self.root.after(200, self.connect)

    def _build(self):
        pad = ttk.Frame(self.root, padding=12)
        pad.pack(fill="both", expand=True)
        row = ttk.Frame(pad)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Plotter:").pack(side="left")
        self.addr_var = tk.StringVar(value=self.host)
        ttk.Entry(row, textvariable=self.addr_var, width=16).pack(side="left", padx=4)
        ttk.Button(row, text="Discover", command=self._discover).pack(side="left")
        ttk.Button(row, text="Connect", command=self.connect).pack(side="left", padx=4)

        ttk.Label(pad, wraplength=400, justify="left", text=(
            "Interact with the video window:\n"
            "  • click = tap\n"
            "  • click-and-drag = pan / swipe\n\n"
            "Close the video window or this panel to disconnect.")
        ).pack(fill="x", pady=4)

        self.status = tk.StringVar(value="Not connected.")
        ttk.Label(pad, textvariable=self.status, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

    def _discover(self):
        self.status.set("Discovering…")
        self.root.update_idletasks()
        svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
        if not svcs:
            messagebox.showinfo("Discover", "No Helm device found.\nJoin the plotter's Wi-Fi.")
            self.status.set("No device found")
            return
        s = svcs[0]
        self.addr_var.set(s.address or s.host)
        self.status.set(f"Found {s.name} at {s.address}")

    def connect(self):
        host = self.addr_var.get().strip()
        if not host:
            return
        self.host = host
        try:
            if self.client:
                self.client.close()
            self.client = HelmClient(host)
            self.client.connect()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Connect", f"Helm session failed: {e}\n\n"
                                 "Paired (helm-cli.py pair) and App-permission "
                                 "= View and Control?")
            self.status.set(f"Session error: {e}")
            return
        if not self.client.touch_ctx:
            self.status.set("Session up but NO touch context — control disabled "
                            "(check App-permission).")
        else:
            self.status.set(f"Connected {host}. Control enabled "
                            f"(ctx {self.client.touch_ctx.hex()}). Use the video window.")
        self._start_video()

    def _start_video(self):
        if self.player and self.player.poll() is None:
            self.player.terminate()
        try:
            if os.path.exists(self.ipc_path):
                os.remove(self.ipc_path)
        except OSError:
            pass
        try:
            self.player = video.play_with_input(self.client.rtsp_url, self.ipc_path)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Video", str(e))
            self.status.set(f"Video error: {e}")
            return
        self._running = True
        self._ipc_thread = threading.Thread(target=self._ipc_loop, daemon=True)
        self._ipc_thread.start()

    def _ipc_loop(self):
        # wait for mpv to create the socket, then stream its events
        sock = None
        for _ in range(100):
            if not self._running:
                return
            if os.path.exists(self.ipc_path):
                try:
                    sock = socket.socket(socket.AF_UNIX)
                    sock.connect(self.ipc_path)
                    break
                except OSError:
                    sock = None
            time.sleep(0.1)
        if not sock:
            return
        buf = b""
        sock.settimeout(0.5)
        while self._running:
            try:
                data = sock.recv(8192)
            except socket.timeout:
                if self.player and self.player.poll() is not None:
                    break  # mpv exited
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self._handle_ipc(line)
        sock.close()

    def _handle_ipc(self, line: bytes):
        try:
            msg = json.loads(line)
        except ValueError:
            return
        if msg.get("event") != "client-message":
            return
        args = msg.get("args", [])
        if len(args) == 4 and args[0] == "helm_touch":
            state, nx, ny = args[1], float(args[2]), float(args[3])
            self._touch(state, nx, ny)

    def _touch(self, state: str, nx: float, ny: float):
        if not self.client or not self.client.touch_ctx:
            return
        try:
            if state == "down":
                self.client.touch(nx, ny, True, new_gesture=True)
            elif state == "move":
                self.client.touch(nx, ny, True)
            elif state == "up":
                self.client.touch(nx, ny, False)
        except OSError:
            pass

    def shutdown(self):
        self._running = False
        if self.player and self.player.poll() is None:
            self.player.terminate()
        if self.client:
            self.client.close()
        try:
            os.remove(self.ipc_path)
        except OSError:
            pass


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Garmin Helm Linux GUI")
    ap.add_argument("--host", help="plotter IP (else use Discover)")
    args = ap.parse_args(argv)

    root = tk.Tk()
    gui = HelmGui(root, args.host)
    root.protocol("WM_DELETE_WINDOW", lambda: (gui.shutdown(), root.destroy()))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
