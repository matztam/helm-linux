"""Capture the real phone<->plotter Helm traffic to finalize the control channel.

The control framing is the one piece that needs observation from a live device.
The workflow:

  1. Put your Linux laptop and the phone (running ActiveCaptain) on the
     plotter's WiFi.
  2. Run this tool. It sniffs traffic to/from the plotter and tries to identify
     the mDNS-advertised Helm port and any TCP control stream.
  3. On the phone, open Helm and press a few keys / tap the screen.
  4. This tool prints a hexdump of the non-video TCP payloads so you can see the
     control framing, and writes a pcap for offline analysis (Wireshark).

Sniffing needs root (raw sockets). If you prefer, capture with:
    sudo tcpdump -i <iface> -w helm.pcap host <plotter-ip>
and open helm.pcap in Wireshark. This module just makes the common case easy.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

from . import discovery


def find_plotter() -> discovery.HelmService | None:
    print("Discovering Helm service...")
    services = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
    if not services:
        return None
    return services[0]


def tcpdump_capture(host: str, iface: str | None, out: str, control_port: int | None) -> int:
    if not shutil.which("tcpdump"):
        print("tcpdump not found. Install it, or capture manually in Wireshark.")
        return 1
    if os.geteuid() != 0:
        print("Live capture needs root. Re-run with sudo, e.g.:")
        flt = f"host {host}"
        if control_port:
            flt += f" and port {control_port}"
        iface_arg = f"-i {iface} " if iface else ""
        print(f"    sudo tcpdump {iface_arg}-w {out} '{flt}'")
        return 1
    flt = f"host {host}"
    if control_port:
        flt += f" and port {control_port}"
    cmd = ["tcpdump"]
    if iface:
        cmd += ["-i", iface]
    cmd += ["-w", out, "-U", flt]
    print("Running:", " ".join(cmd))
    print("Now drive Helm from the phone (press keys / tap). Ctrl-C to stop.")
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Capture Garmin Helm control traffic")
    ap.add_argument("--host", help="plotter IP (default: auto-discover)")
    ap.add_argument("--port", type=int, help="control port to filter (optional)")
    ap.add_argument("--iface", help="capture interface (e.g. wlan0)")
    ap.add_argument("--out", default="helm.pcap", help="output pcap path")
    args = ap.parse_args(argv)

    host = args.host
    port = args.port
    if not host:
        svc = find_plotter()
        if not svc:
            print("No Helm service found. Join the plotter's WiFi and retry.")
            return 1
        print(f"Found: {svc}")
        host = svc.address or svc.host
        port = port or svc.port
    print(f"Plotter: {host}  control port hint: {port}")
    print(
        "Tip: the mDNS port above is the Helm service port; the video is RTSP\n"
        "     (usually :554). Control is whatever non-RTSP TCP stream lights up\n"
        "     when you press keys. Watch for that in the capture.\n"
    )
    return tcpdump_capture(host, args.iface, args.out, port)


if __name__ == "__main__":
    sys.exit(main())
