#!/usr/bin/env python3
"""garmin-helm-linux — command-line tool.

Subcommands:
    discover            find Garmin Helm devices on the Wi-Fi (mDNS)
    pair                register this machine with the plotter (one-time)
    helm                open the Helm session and play the video (main command)
    view <url>          play any RTSP/MJPEG stream (mpv/ffplay/vlc)
    analyze <pcap>      decode a captured Helm session

Typical use: `pair` once (accept on the plotter, set App-permission to
View and Control), then `helm` — or run the GUI, helm-gui.py.
"""

from __future__ import annotations

import argparse
import sys

from helm import discovery, video


def cmd_discover(args) -> int:
    types = discovery.GARMIN_SERVICE_TYPES if args.all else [discovery.HELM_SERVICE]
    label = "all Garmin services" if args.all else "Helm devices"
    print(f"Browsing for {label} (~{args.timeout:.0f}s)…")
    results = discovery.browse(types, timeout=args.timeout)
    if not results:
        print("Nothing found. Are you on the plotter's Wi-Fi network?")
        return 1
    for s in results:
        print(f"\n  {s.name}")
        print(f"      service : {s.service_type}")
        print(f"      address : {s.address or s.host}:{s.port}")
        for k, v in s.txt.items():
            print(f"      txt     : {k}={v}")
    return 0


def cmd_pair(args) -> int:
    from helm import credential
    if args.reset:
        return credential.reset_identity()
    if args.list:
        return credential.list_users(args.host, args.port)
    return credential.probe(args.host, args.port, role=args.role)


def cmd_helm(args) -> int:
    from helm.helm_client import HelmClient
    host = args.host
    if not host:
        svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
        if not svcs:
            print("No Helm device found. Join the plotter's Wi-Fi.")
            return 1
        if len(svcs) > 1:
            print("Multiple plotters found — pick one with --host <ip>:")
            for s in svcs:
                print(f"  {s.name}  ->  --host {s.address or s.host}")
            return 1
        host = svcs[0].address or svcs[0].host
        print(f"Found {svcs[0].name} at {host}")
    client = HelmClient(host)
    print(f"Opening Helm session {host}:{client.port} …")
    try:
        client.connect()
    except OSError as e:
        print(f"  session failed: {e}\n  (paired? App-permission View and Control?)")
        return 1
    print(f"  handshake ok; touch control: "
          f"{'enabled' if client.touch_ctx else 'NOT granted (check permission)'}")
    print(f"  video: {client.rtsp_url}")
    if args.tap:
        client.tap(*args.tap)
        print(f"  sent test tap at {tuple(args.tap)}")
    if args.no_video:
        client.close()
        return 0
    rc = video.play_supervised(client.rtsp_url, title="Garmin Helm")
    client.close()
    return rc


def cmd_view(args) -> int:
    return video.play(args.url, player=args.player)


def cmd_analyze(args) -> int:
    from helm import analyze
    return analyze.analyze(args.pcap, args.port)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="helm-cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover", help="find Helm devices on the network")
    p.add_argument("--all", action="store_true", help="show all Garmin services")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("pair", help="register this machine with the plotter")
    p.add_argument("--host", help="bl-id service IP (default: auto-discover)")
    p.add_argument("--port", type=int, help="bl-id service port (default 80)")
    p.add_argument("--role", default="guest", choices=["guest", "owner", "dealer"])
    p.add_argument("--reset", action="store_true", help="forget the saved identity")
    p.add_argument("--list", action="store_true", help="list registered users")
    p.set_defaults(func=cmd_pair)

    p = sub.add_parser("helm", help="open the Helm session + play video (main command)")
    p.add_argument("--host", help="plotter IP (default: auto-discover)")
    p.add_argument("--tap", nargs=2, type=float, metavar=("X", "Y"),
                   help="send a test tap at normalized 0..1 coords, then play")
    p.add_argument("--no-video", action="store_true", help="session only, no player")
    p.set_defaults(func=cmd_helm)

    p = sub.add_parser("view", help="play any RTSP/MJPEG stream")
    p.add_argument("url")
    p.add_argument("--player", choices=["mpv", "ffplay", "vlc"])
    p.set_defaults(func=cmd_view)

    p = sub.add_parser("analyze", help="decode a captured Helm session pcap")
    p.add_argument("pcap")
    p.add_argument("--port", type=int, default=51200)
    p.set_defaults(func=cmd_analyze)

    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
