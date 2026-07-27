#!/usr/bin/env python3
"""garmin-helm-linux GUI (GStreamer/GTK) — live chartplotter view + touch
control on Linux, video embedded in-process instead of driving an external
mpv window over IPC.

Rationale: mpv as a separate process (helm-gui.py) sometimes exits cleanly
(exit 0) when the RTSP/UDP stream stalls -- e.g. GStreamer/FFmpeg/mpv have
different RTCP/timeout behavior over the plotter's UDP-only RTSP transport --
and a clean exit reads as "user closed the window", tearing down the whole
session instead of just reconnecting the video. GStreamer's rtspsrc handles
UDP RTCP receiver reports and reconnection internally, and rendering into a
GtkWidget (gtksink) keeps video + touch input in one process/window: no IPC
socket, no child-process lifecycle to interpret.

Requires: python3-gi, gir1.2-gtk-3.0, gstreamer1.0-plugins-good (gtksink),
gstreamer1.0-plugins-bad (rtspsrc), a GTK+ GStreamer-compatible Python (the
system python3, not a venv without system site-packages).

Prereqs (one-time): register this machine -- `python3 helm-cli.py pair` on the
plotter's Wi-Fi -- and set the plotter's global App-permission to
"View and Control".
"""

from __future__ import annotations

import json
import os
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("Gst", "1.0")
gi.require_version("GstVideo", "1.0")
from gi.repository import Gdk, GLib, Gst, GstVideo, Gtk  # noqa: E402

from helm import discovery  # noqa: E402
from helm.helm_client import HelmClient  # noqa: E402

Gst.init(None)


class VideoWidget(Gtk.Bin):
    """Owns a GStreamer pipeline (rtspsrc ! decodebin ! gtksink) and reports
    normalized [0,1] pointer press/move/release/scroll via callbacks. Video
    reconnection (rtspsrc's own UDP/RTCP handling, plus a restart on EOS/ERROR)
    is entirely internal -- callers only see "connected"/"disconnected"."""

    def __init__(self, on_touch, on_scroll, on_state):
        super().__init__()
        self._on_touch = on_touch      # (state: 'down'|'move'|'up', x, y) -> None
        self._on_scroll = on_scroll    # (direction: 'up'|'down', x, y) -> None
        self._on_state = on_state      # (text: str) -> None
        self._pipeline: Gst.Pipeline | None = None
        self._sink_widget: Gtk.Widget | None = None
        self._url: str | None = None
        self._pressed = False
        self._restart_pending = False

        self._box = Gtk.EventBox()
        # Receive events before the child widget (gtksink) gets a chance to
        # consume them -- without this, scroll-event never reaches us once
        # the video sink is added as a child (button/motion still worked
        # because GTK routes those to the EventBox regardless, but scroll
        # apparently doesn't propagate up from gtksink's own GDK window).
        self._box.set_above_child(True)
        self._box.set_size_request(640, 360)
        self._placeholder = Gtk.Label(label="Not connected")
        self._box.add(self._placeholder)
        self.add(self._box)

        self._box.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK
            | Gdk.EventMask.BUTTON_RELEASE_MASK
            | Gdk.EventMask.POINTER_MOTION_MASK
            | Gdk.EventMask.SCROLL_MASK
            | Gdk.EventMask.SMOOTH_SCROLL_MASK
        )
        self._box.connect("button-press-event", self._on_button)
        self._box.connect("button-release-event", self._on_button)
        self._box.connect("motion-notify-event", self._on_motion)
        self._box.connect("scroll-event", self._on_scroll_event)

    # ---- pointer -> normalized coords -------------------------------------
    def _norm_xy(self, widget: Gtk.Widget, ex: float, ey: float):
        alloc = widget.get_allocation()
        if alloc.width <= 0 or alloc.height <= 0:
            return None
        x = min(1.0, max(0.0, ex / alloc.width))
        y = min(1.0, max(0.0, ey / alloc.height))
        return x, y

    def _on_button(self, widget, event):
        if event.button != 1:
            return False
        xy = self._norm_xy(widget, event.x, event.y)
        if xy is None:
            return False
        if event.type == Gdk.EventType.BUTTON_PRESS:
            self._pressed = True
            self._on_touch("down", *xy)
        elif event.type == Gdk.EventType.BUTTON_RELEASE:
            self._pressed = False
            self._on_touch("up", *xy)
        return True

    def _on_motion(self, widget, event):
        if not self._pressed:
            return False
        xy = self._norm_xy(widget, event.x, event.y)
        if xy is None:
            return False
        self._on_touch("move", *xy)
        return True

    def _on_scroll_event(self, widget, event):
        xy = self._norm_xy(widget, event.x, event.y)
        if xy is None:
            return False
        if event.direction == Gdk.ScrollDirection.UP:
            self._on_scroll("up", *xy)
        elif event.direction == Gdk.ScrollDirection.DOWN:
            self._on_scroll("down", *xy)
        elif event.direction == Gdk.ScrollDirection.SMOOTH:
            # Many touchpads/mice (esp. under Wayland) only ever send SMOOTH
            # scroll events with a delta, never discrete UP/DOWN.
            _ok, _dx, dy = event.get_scroll_deltas()
            if dy < 0:
                self._on_scroll("up", *xy)
            elif dy > 0:
                self._on_scroll("down", *xy)
        return True

    # ---- pipeline ----------------------------------------------------------
    def start(self, rtsp_url: str) -> None:
        self.stop()
        self._url = rtsp_url
        desc = (
            f'rtspsrc location="{rtsp_url}" protocols=udp latency=100 '
            f"retry=5 timeout=5000000 tcp-timeout=5000000 "
            f"! decodebin ! videoconvert ! gtksink name=vsink sync=false"
        )
        self._pipeline = Gst.parse_launch(desc)
        sink = self._pipeline.get_by_name("vsink")
        self._sink_widget = sink.props.widget
        self._sink_widget.set_size_request(640, 360)

        child = self._box.get_child()
        if child:
            self._box.remove(child)
        self._box.add(self._sink_widget)
        # The EventBox's event mask alone isn't enough once a new child is
        # swapped in after the window is already realized (show_all() already
        # ran) -- the child's own GDK window needs the mask too, or events
        # like scroll silently stop reaching us (button/motion still worked,
        # apparently routed differently). Confirmed by isolated repro.
        self._sink_widget.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK
            | Gdk.EventMask.BUTTON_RELEASE_MASK
            | Gdk.EventMask.POINTER_MOTION_MASK
            | Gdk.EventMask.SCROLL_MASK
            | Gdk.EventMask.SMOOTH_SCROLL_MASK
        )
        self._sink_widget.show()

        bus = self._pipeline.get_bus()
        bus.add_signal_watch()
        bus.connect("message", self._on_bus_message)

        self._pipeline.set_state(Gst.State.PLAYING)
        self._on_state(f"Connecting video: {rtsp_url}")

    def stop(self) -> None:
        if self._pipeline is not None:
            self._pipeline.set_state(Gst.State.NULL)
            self._pipeline = None
        self._sink_widget = None
        child = self._box.get_child()
        if child:
            self._box.remove(child)
        self._box.add(self._placeholder)
        self._placeholder.show()

    def _on_bus_message(self, bus, msg):
        t = msg.type
        if t == Gst.MessageType.ERROR:
            err, dbg = msg.parse_error()
            self._on_state(f"Video error: {err} — reconnecting…")
            self._schedule_restart()
        elif t == Gst.MessageType.EOS:
            self._on_state("Video stream ended — reconnecting…")
            self._schedule_restart()
        elif t == Gst.MessageType.STATE_CHANGED and msg.src == self._pipeline:
            _old, new, _pending = msg.parse_state_changed()
            if new == Gst.State.PLAYING:
                self._on_state(f"Live: {self._url} — click/drag to control")
        return True

    def _schedule_restart(self):
        if self._restart_pending or self._url is None:
            return
        self._restart_pending = True

        def restart():
            self._restart_pending = False
            if self._url is not None:
                self.start(self._url)
            return False

        GLib.timeout_add(1000, restart)


class HelmGtkGui:
    def __init__(self, host: str | None):
        self.host = host or ""
        self.client: HelmClient | None = None
        self._running = False
        self._zoom_busy = threading.Lock()
        self._settings = os.path.join(os.path.dirname(__file__), "helm-gui.json")

        self.window = Gtk.Window(title="Garmin Helm — control (GStreamer)")
        self.window.set_default_size(900, 560)
        self.window.connect("destroy", self._on_quit)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        outer.set_border_width(8)
        self.window.add(outer)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        outer.pack_start(row, False, False, 0)
        row.pack_start(Gtk.Label(label="Plotter:"), False, False, 0)
        self.addr_entry = Gtk.Entry()
        self.addr_entry.set_width_chars(16)
        self.addr_entry.set_text(self.host)
        row.pack_start(self.addr_entry, False, False, 0)
        discover_btn = Gtk.Button(label="Discover")
        discover_btn.connect("clicked", self._on_discover)
        row.pack_start(discover_btn, False, False, 0)
        self.connect_btn = Gtk.Button(label="Connect")
        self.connect_btn.connect("clicked", self._on_toggle_connect)
        row.pack_start(self.connect_btn, False, False, 0)
        quit_btn = Gtk.Button(label="Quit")
        quit_btn.connect("clicked", lambda _b: self.window.destroy())
        row.pack_end(quit_btn, False, False, 0)

        hint = Gtk.Label(
            label="Interact with the video: click = tap, click-and-drag = pan, "
                  "scroll = zoom.",
            xalign=0,
        )
        outer.pack_start(hint, False, False, 0)

        self.video = VideoWidget(self._on_touch, self._on_scroll, self._set_status)
        outer.pack_start(self.video, True, True, 0)

        self.status_label = Gtk.Label(label="Not connected.", xalign=0)
        outer.pack_end(self.status_label, False, False, 0)

        self.window.show_all()

        last = self._load_last_host()
        if last and not self.host:
            self.addr_entry.set_text(last)
        if self.host:
            GLib.timeout_add(200, self._connect_once)
        else:
            GLib.timeout_add(200, self._auto_start_once)

    # ---- persistence -------------------------------------------------------
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

    # ---- status (main-thread-safe from GLib.idle_add) ----------------------
    def _set_status(self, text: str) -> None:
        GLib.idle_add(self.status_label.set_text, text)

    # ---- discovery ----------------------------------------------------------
    def _auto_start_once(self):
        self._set_status("Searching for plotters…")

        def work():
            svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
            GLib.idle_add(self._auto_pick, svcs)

        threading.Thread(target=work, daemon=True).start()
        return False

    def _auto_pick(self, svcs):
        if not svcs:
            saved = self.addr_entry.get_text().strip()
            if saved:
                self._connect_once()
            else:
                self._set_status("No plotter found — join the plotter's Wi-Fi, "
                                 "then Discover.")
            return False
        saved = self._load_last_host()
        match = next((s for s in svcs if (s.address or s.host) == saved), None)
        s = match or svcs[0]
        self.addr_entry.set_text(s.address or s.host)
        self._connect_once()
        return False

    def _on_discover(self, _btn):
        self._set_status("Discovering…")

        def work():
            svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
            GLib.idle_add(self._discover_done, svcs)

        threading.Thread(target=work, daemon=True).start()

    def _discover_done(self, svcs):
        if not svcs:
            self._set_status("No device found.")
            return False
        s = svcs[0]
        self.addr_entry.set_text(s.address or s.host)
        self._set_status(f"Selected {s.name} at {s.address}. Click Connect.")
        return False

    # ---- connect / disconnect ----------------------------------------------
    def _on_toggle_connect(self, _btn):
        if self._running:
            self.disconnect()
        else:
            self._connect_once()

    def _connect_once(self):
        self.connect()
        return False

    def connect(self):
        host = self.addr_entry.get_text().strip()
        if not host:
            return
        self.host = host
        self._set_status(f"Connecting to {host}…")
        try:
            if self.client:
                self.client.close()
            self.client = HelmClient(host)
            self.client.connect()
        except OSError as e:
            self._set_status(f"Session error: {e} — paired and permission set to "
                             "View and Control?")
            return
        self._save_last_host(host)
        self._running = True
        self.connect_btn.set_label("Disconnect")
        if not self.client.touch_ctx:
            self._set_status("Session up but NO touch context — control disabled "
                             "(check App-permission).")
        else:
            self._set_status(f"Connected {host}. Control enabled.")
        self.video.start(self.client.rtsp_url)

    def disconnect(self):
        self._running = False
        self.video.stop()
        if self.client:
            self.client.close()
            self.client = None
        self.connect_btn.set_label("Connect")
        self._set_status("Disconnected. Click Connect to reconnect.")

    # ---- touch/scroll -> Helm session ---------------------------------------
    def _on_touch(self, state: str, nx: float, ny: float) -> None:
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

    def _on_scroll(self, direction: str, nx: float, ny: float) -> None:
        """client.zoom() sends several 0x164c frames with ~20ms sleeps between
        them (~150-200ms total). Smooth-scroll delivers a burst of many
        scroll-events per mouse "click" of wheel travel; calling zoom()
        synchronously in the GTK main loop for each one serializes all that
        sleeping on the UI thread and the whole window freezes. Run it in a
        background thread instead, and drop (don't queue) overlapping scrolls
        so a burst can't pile up an ever-growing backlog of pending zooms."""
        if not self.client or not self.client.can_zoom:
            return
        if not self._zoom_busy.acquire(blocking=False):
            return  # a zoom is already in flight — drop this one
        client = self.client

        def work():
            try:
                client.zoom(1 if direction == "up" else -1, nx, ny)
            except OSError:
                pass
            finally:
                self._zoom_busy.release()

        threading.Thread(target=work, daemon=True).start()

    def _on_quit(self, _widget):
        self._running = False
        self.video.stop()
        if self.client:
            self.client.close()
        Gtk.main_quit()


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Garmin Helm Linux GUI (GStreamer/GTK)")
    ap.add_argument("--host", help="plotter IP (else use Discover)")
    args = ap.parse_args(argv)

    HelmGtkGui(args.host)
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
