#!/usr/bin/env python3.13
"""Capture the phone<->plotter Helm traffic by ARP-spoofing through this laptop.

Wi-Fi encrypts each station's unicast, so you can't passively sniff the phone's
traffic. This tool ARP-poisons the phone and the plotter so their packets route
through the laptop, enables IP forwarding (so they keep talking), and runs
tcpdump on the Helm control port. Then you pinch on the phone and we get the
multi-touch bytes.

Run with python3.13 (which has scapy here) as root:

    sudo python3.13 tools/capture.py --phone <PHONE_IP> --iface <WIFI_IFACE>

  * PHONE_IP: your phone's Wi-Fi address (phone Settings -> Wi-Fi -> the network
    -> IP). This tool also prints the plotter's connected-stations list to help.
  * WIFI_IFACE: e.g. wlan0  (see `ip link`)

While it runs, on the PHONE open ActiveCaptain -> Helm and pinch-zoom in and out
a few times, then Ctrl-C here. Analyze with:

    python3 helm-cli.py analyze helm-pinch.pcap --port 51200

Only works on a network that allows client-to-client traffic (a plotter's own
AP normally does). Restores ARP tables and IP forwarding on exit.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request


def connected_stations(plotter: str):
    try:
        url = f"http://{plotter}/garmin/swifi/api/ap/connected_stations"
        with urllib.request.urlopen(url, timeout=4) as r:
            return json.load(r)
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phone", help="phone Wi-Fi IP")
    ap.add_argument("--plotter", default="172.16.6.0")
    ap.add_argument("--iface", required=True, help="Wi-Fi interface, e.g. wlan0")
    ap.add_argument("--out", default="helm-pinch.pcap")
    ap.add_argument("--port", type=int, default=51200, help="Helm control port")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Run as root (sudo).")
        return 1
    try:
        from scapy.all import ARP, Ether, conf, sendp, srp
    except ImportError:
        print("scapy missing. Install for this interpreter:\n"
              "  python3.13 -m pip install --break-system-packages scapy")
        return 1
    conf.verb = 0
    conf.iface = args.iface

    if not args.phone:
        info = connected_stations(args.plotter)
        print("Plotter connected stations:", json.dumps(info) if info else "(unavailable)")
        print("Pass the phone's IP with --phone (from the phone's Wi-Fi settings).")
        return 1

    def mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=3, retry=2, iface=args.iface)
        for _, r in ans:
            return r.hwsrc
        return None

    pm, gm = mac(args.phone), mac(args.plotter)
    if not pm or not gm:
        print(f"Could not ARP-resolve (phone={pm}, plotter={gm}). Both online?")
        return 1
    print(f"phone   {args.phone} = {pm}")
    print(f"plotter {args.plotter} = {gm}")

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    stop = threading.Event()

    def spoof():
        while not stop.is_set():
            sendp(Ether(dst=pm) / ARP(op=2, pdst=args.phone, hwdst=pm,
                                      psrc=args.plotter), iface=args.iface)
            sendp(Ether(dst=gm) / ARP(op=2, pdst=args.plotter, hwdst=gm,
                                      psrc=args.phone), iface=args.iface)
            time.sleep(2)

    threading.Thread(target=spoof, daemon=True).start()
    flt = f"host {args.plotter} and port {args.port}"
    print(f"\nARP spoofing + capturing '{flt}' -> {args.out}")
    print(">>> On the PHONE: open Helm and PINCH-ZOOM in and out a few times. <<<")
    print("    (Ctrl-C here when done.)\n")
    tcp = subprocess.Popen(["tcpdump", "-i", args.iface, "-w", args.out, "-U", flt])
    try:
        tcp.wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if tcp.poll() is None:
            tcp.terminate()
        time.sleep(0.3)
        # restore both ARP caches to the true MACs
        sendp(Ether(dst=pm) / ARP(op=2, pdst=args.phone, hwdst=pm,
                                  psrc=args.plotter, hwsrc=gm), count=3, iface=args.iface)
        sendp(Ether(dst=gm) / ARP(op=2, pdst=args.plotter, hwdst=gm,
                                  psrc=args.phone, hwsrc=pm), count=3, iface=args.iface)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print(f"\nStopped. Analyze:\n  python3 helm-cli.py analyze {args.out} --port {args.port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
