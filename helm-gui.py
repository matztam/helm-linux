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
        self._ipc_base = os.path.join(tempfile.gettempdir(), f"helm-mpv-{os.getpid()}")
        self._video_thread: threading.Thread | None = None
        self._running = False        # session active
        self._video_running = False  # video supervisor should keep mpv alive
        self._launch = 0             # mpv launch counter (fresh socket per launch)
        self._settings = os.path.join(os.path.dirname(__file__), "helm-gui.json")

        root.title("Garmin Helm — control")
        root.geometry("440x220")
        self._build()
        # Prefill the last-used plotter, then start: connect to an explicit
        # --host, otherwise auto-discover.
        last = self._load_last_host()
        if last and not self.host:
            self.addr_var.set(last)
        if self.host:
            self.root.after(200, self.connect)
        else:
            self.root.after(200, self._auto_start)

    def _load_last_host(self) -> str:
        try:
            with open(self._settings) as f:
                return json.load(f).get("last_host", "")
        except (OSError, ValueError):
            return ""

    def _save_last_host(self, host: str) -> None:
        try:
            with open(self._settings, "w") as f:
                json.dump({"last_host": host}, f)
        except OSError:
            pass

    def _auto_start(self):
        """Discover in the background on launch and connect automatically."""
        self.status.set("Searching for plotters…")
        def work():
            svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
            self.root.after(0, lambda: self._auto_pick(svcs))
        threading.Thread(target=work, daemon=True).start()

    def _auto_pick(self, svcs):
        if not svcs:
            saved = self.addr_var.get().strip()
            if saved:  # mDNS can be flaky; try the remembered plotter anyway
                self.connect(quiet=True)
            else:
                self.status.set("No plotter found — join the plotter's Wi-Fi, "
                                "then Discover.")
            return
        saved = self._load_last_host()
        match = next((s for s in svcs if (s.address or s.host) == saved), None)
        if match:
            s = match
        elif len(svcs) == 1:
            s = svcs[0]
        else:
            s = self._choose_plotter(svcs)
            if not s:
                self.status.set(f"{len(svcs)} plotters found — pick one.")
                return
        self.addr_var.set(s.address or s.host)
        self.connect(quiet=True)

    def _build(self):
        pad = ttk.Frame(self.root, padding=12)
        pad.pack(fill="both", expand=True)
        row = ttk.Frame(pad)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Plotter:").pack(side="left")
        self.addr_var = tk.StringVar(value=self.host)
        ttk.Entry(row, textvariable=self.addr_var, width=16).pack(side="left", padx=4)
        ttk.Button(row, text="Discover", command=self._discover).pack(side="left")
        self.connect_btn = ttk.Button(row, text="Connect", command=self._toggle_connect)
        self.connect_btn.pack(side="left", padx=4)
        ttk.Button(row, text="Quit", command=self._quit).pack(side="right")

        ttk.Label(pad, wraplength=400, justify="left", text=(
            "Interact with the video window:\n"
            "  • click = tap\n"
            "  • click-and-drag = pan / swipe\n"
            "  • scroll wheel = zoom in / out")
        ).pack(fill="x", pady=4)

        self.status = tk.StringVar(value="Not connected.")
        ttk.Label(pad, textvariable=self.status, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

    def _toggle_connect(self):
        if self._running:
            self.disconnect()
        else:
            self.connect()

    def _quit(self):
        self.shutdown()
        self.root.destroy()

    def _discover(self):
        self.status.set("Discovering…")
        self.root.update_idletasks()
        svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
        if not svcs:
            messagebox.showinfo("Discover", "No Helm device found.\nJoin the plotter's Wi-Fi.")
            self.status.set("No device found")
            return
        s = svcs[0] if len(svcs) == 1 else self._choose_plotter(svcs)
        if not s:
            self.status.set(f"{len(svcs)} plotters found — pick one.")
            return
        self.addr_var.set(s.address or s.host)
        self.status.set(f"Selected {s.name} at {s.address}. Click Connect.")

    def _choose_plotter(self, svcs):
        """Modal picker when more than one plotter is on the network."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Select plotter")
        dlg.transient(self.root)
        dlg.grab_set()
        ttk.Label(dlg, text="Multiple plotters found — choose one:",
                  padding=8).pack(anchor="w")
        lb = tk.Listbox(dlg, width=44, height=min(8, len(svcs)))
        for s in svcs:
            lb.insert("end", f"{s.name}   ({s.address or s.host})")
        lb.selection_set(0)
        lb.pack(fill="both", expand=True, padx=8)
        chosen = {"s": None}

        def ok():
            sel = lb.curselection()
            if sel:
                chosen["s"] = svcs[sel[0]]
            dlg.destroy()

        row = ttk.Frame(dlg, padding=8)
        row.pack(fill="x")
        ttk.Button(row, text="Connect", command=ok).pack(side="right")
        ttk.Button(row, text="Cancel", command=dlg.destroy).pack(side="right", padx=4)
        lb.bind("<Double-Button-1>", lambda _e: ok())
        self.root.wait_window(dlg)
        return chosen["s"]

    def connect(self, quiet: bool = False):
        host = self.addr_var.get().strip()
        if not host:
            return
        self.host = host
        self.status.set(f"Connecting to {host}…")
        self.root.update_idletasks()
        try:
            if self.client:
                self.client.close()
            self.client = HelmClient(host)
            self.client.connect()
        except Exception as e:  # noqa: BLE001
            msg = (f"Helm session failed: {e}\n\nPaired (helm-cli.py pair) and "
                   "App-permission = View and Control?")
            if not quiet:  # don't nag with a popup on auto-connect at launch
                messagebox.showerror("Connect", msg)
            self.status.set(f"Session error: {e}")
            return
        self._save_last_host(host)
        self._running = True   # session is up (drives the video supervisor)
        self.connect_btn.config(text="Disconnect")
        if not self.client.touch_ctx:
            self.status.set("Session up but NO touch context — control disabled "
                            "(check App-permission).")
        else:
            self.status.set(f"Connected {host}. Control enabled "
                            f"(ctx {self.client.touch_ctx.hex()}). Use the video window.")
        self._start_video()

    def disconnect(self):
        self._running = False
        self._video_running = False
        if self.player and self.player.poll() is None:
            self.player.terminate()
        if self.client:
            self.client.close()
            self.client = None
        self.connect_btn.config(text="Connect")
        self.status.set("Disconnected. Click Connect to reconnect.")

    def _start_video(self):
        # (re)start the supervisor that keeps mpv alive across crashes
        self._video_running = False
        if self._video_thread and self._video_thread.is_alive():
            self._video_thread.join(timeout=1.0)
        self._video_running = True
        self._video_thread = threading.Thread(target=self._video_supervisor, daemon=True)
        self._video_thread.start()

    def _set_status(self, text: str):
        """Thread-safe status update."""
        self.root.after(0, lambda: self.status.set(text))

    def _video_supervisor(self):
        """Keep mpv running: relaunch it if it crashes (corrupt stream, etc.)
        while the session is up. The Helm session/touch context is unaffected."""
        backoff = 0.5
        while self._running and self._video_running:
            self._launch += 1
            ipc_path = f"{self._ipc_base}-{self._launch}.sock"
            try:
                if os.path.exists(ipc_path):
                    os.remove(ipc_path)
            except OSError:
                pass
            try:
                self.player = video.play_with_input(self.client.rtsp_url, ipc_path)
            except Exception as e:  # noqa: BLE001  (e.g. mpv missing)
                self._set_status(f"Video error: {e}")
                return
            started = time.monotonic()
            self._set_status(f"Live: {self.client.rtsp_url} — click/drag to control")
            self._ipc_read(ipc_path)  # blocks until mpv exits or we stop
            rc = self.player.poll()
            if rc is None:
                self.player.terminate()
            try:
                os.remove(ipc_path)
            except OSError:
                pass
            if not (self._running and self._video_running):
                break  # we're shutting down / reconnecting
            if rc == 0:
                # clean exit == user closed the video window -> disconnect too
                self._video_running = False
                self.root.after(0, self.disconnect)
                break
            # non-zero exit == crash (corrupt stream, decoder, etc.) -> restart.
            # Reset backoff if it had been running a while (a transient glitch).
            backoff = 0.5 if time.monotonic() - started > 8 else min(backoff * 2, 5.0)
            self._set_status(f"Video crashed (exit {rc}) — restarting in {backoff:.0f}s…")
            end = time.monotonic() + backoff
            while time.monotonic() < end and self._running and self._video_running:
                time.sleep(0.1)

    def _ipc_read(self, ipc_path: str):
        """Connect to mpv's IPC socket and forward touch events until mpv exits."""
        sock = None
        for _ in range(100):
            if not (self._running and self._video_running):
                return
            if os.path.exists(ipc_path):
                try:
                    sock = socket.socket(socket.AF_UNIX)
                    sock.connect(ipc_path)
                    break
                except OSError:
                    sock = None
            time.sleep(0.1)
        if not sock:
            return  # mpv never came up; supervisor will retry
        buf = b""
        sock.settimeout(0.5)
        while self._running and self._video_running:
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
            self._touch(args[1], float(args[2]), float(args[3]))
        elif len(args) == 4 and args[0] == "helm_scroll":
            self._scroll(args[1], float(args[2]), float(args[3]))

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

    def _scroll(self, direction: str, nx: float, ny: float):
        if not self.client or not self.client.can_zoom:
            return
        try:
            self.client.zoom(1 if direction == "up" else -1, nx, ny)
        except OSError:
            pass

    def shutdown(self):
        self._running = False
        self._video_running = False
        if self.player and self.player.poll() is None:
            self.player.terminate()
        if self.client:
            self.client.close()


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
