#!/usr/bin/env python3
"""garmin-helm-linux command-line tool.

Subcommands:
    discover              browse the WiFi for Garmin Helm devices
    probe   <rtsp-url>    OPTIONS/DESCRIBE an RTSP stream, print the SDP
    view    <url>         play an RTSP/MJPEG stream (mpv/ffplay/vlc)
    key     <KEY>         send a Helm key (needs finalized control channel)
    tap     <x> <y>       tap normalized (0..1) coords on the plotter
    capture               sniff phone<->plotter traffic to finalize control

Run `discover` first. It prints each device's address, port and TXT records.
"""

from __future__ import annotations

import argparse
import sys

from helm import discovery, video
from helm.control import HelmControlClient, RtspProbe
from helm.keys import HelmKey


def cmd_discover(args) -> int:
    types = discovery.GARMIN_SERVICE_TYPES if args.all else [discovery.HELM_SERVICE]
    label = "all Garmin services" if args.all else "Helm devices"
    print(f"Browsing for {label} (~{args.timeout:.0f}s)...")
    results = discovery.browse(types, timeout=args.timeout)
    if not results:
        print("Nothing found. Are you on the plotter's WiFi network?")
        return 1
    for s in results:
        print(f"\n  {s.name}")
        print(f"      service : {s.service_type}")
        print(f"      address : {s.address or s.host}:{s.port}")
        if s.txt:
            for k, v in s.txt.items():
                print(f"      txt     : {k}={v}")
        hint = s.rtsp_hint
        if hint:
            print(f"      rtsp    : {hint}")
    return 0


def cmd_probe(args) -> int:
    info = RtspProbe(args.url).describe()
    print("OPTIONS:", ", ".join(info["options"]) or "(none)")
    print("Media/codecs:")
    for c in info["codecs"]:
        print("   ", c)
    print("\n--- SDP ---")
    print(info["sdp"])
    return 0


def cmd_view(args) -> int:
    return video.play(args.url, player=args.player)


def cmd_key(args) -> int:
    try:
        key = HelmKey[args.key] if args.key.startswith("HLM_") else HelmKey["HLM_KEY_" + args.key.upper()]
    except KeyError:
        print(f"Unknown key '{args.key}'. Valid keys:")
        for k in HelmKey:
            print("   ", k.name)
        return 2
    client = HelmControlClient(args.host, args.port, device_id=args.device)
    client.send_key(key)
    client.close()
    return 0


def cmd_tap(args) -> int:
    client = HelmControlClient(args.host, args.port, device_id=args.device)
    client.tap(args.x, args.y)
    client.close()
    return 0


def cmd_capture(args) -> int:
    from helm import capture
    return capture.main(["--host", args.host] if args.host else [])


def cmd_analyze(args) -> int:
    from helm import gmn2
    return gmn2.analyze(args.pcap, args.port)


def cmd_probe_control(args) -> int:
    from helm import probe_control
    return probe_control.probe(args.host, args.port)


def cmd_mitm(args) -> int:
    from helm import mitm
    argv = ["--plotter", args.plotter, "--port", str(args.port)]
    if args.name:
        argv += ["--name", args.name]
    return mitm.main(argv)


def cmd_pair(args) -> int:
    from helm import credential
    if args.reset:
        return credential.reset_identity()
    if args.list:
        return credential.list_users(args.host, args.port)
    return credential.probe(args.host, args.port, role=args.role)


def cmd_connect(args) -> int:
    from helm import session
    return session.connect_probe(args.host, args.port)


def cmd_helm(args) -> int:
    """Open the Helm session and play the video; optionally send a test tap."""
    from helm.helm_client import HelmClient
    host = args.host
    if not host:
        svcs = discovery.browse([discovery.HELM_SERVICE], timeout=5.0)
        if not svcs:
            print("No Helm device found. Join the plotter's Wi-Fi.")
            return 1
        host = svcs[0].address or svcs[0].host
        print(f"Found {svcs[0].name} at {host}")
    client = HelmClient(host)
    print(f"Opening Helm session {host}:51200 …")
    try:
        client.connect()
    except OSError as e:
        print(f"  session failed: {e}\n  (paired? App-permission View and Control?)")
        return 1
    reply = client.read(8192, timeout=2.0)
    print(f"  handshake ok, plotter sent {len(reply)} bytes")
    print(f"  video: {client.rtsp_url}")
    if args.tap:
        x, y = args.tap
        print(f"  sending test tap at ({x}, {y})")
        client.tap(x, y)
    if args.no_video:
        client.close()
        return 0
    print("  launching video (close the player to exit)…")
    rc = video.play(client.rtsp_url, title="Garmin Helm")
    client.close()
    return rc


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="helm-cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover", help="find Helm devices on the network")
    p.add_argument("--all", action="store_true", help="show all Garmin services")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("probe", help="RTSP OPTIONS/DESCRIBE + SDP")
    p.add_argument("url")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("view", help="play the stream")
    p.add_argument("url")
    p.add_argument("--player", choices=["mpv", "ffplay", "vlc"])
    p.set_defaults(func=cmd_view)

    p = sub.add_parser("key", help="send a Helm key")
    p.add_argument("key")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--device", type=int, default=0)
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("tap", help="tap normalized coords")
    p.add_argument("x", type=float)
    p.add_argument("y", type=float)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--device", type=int, default=0)
    p.set_defaults(func=cmd_tap)

    p = sub.add_parser("capture", help="capture control traffic")
    p.add_argument("--host")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("analyze", help="decode a captured pcap as GMN 2.0")
    p.add_argument("pcap")
    p.add_argument("--port", type=int, help="focus TCP port, e.g. 51200")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("probe-control", help="characterize the control port (plaintext/TLS)")
    p.add_argument("host")
    p.add_argument("port", type=int, nargs="?", default=51200)
    p.set_defaults(func=cmd_probe_control)

    p = sub.add_parser("mitm", help="MITM proxy to capture the live GMN2 protocol")
    p.add_argument("--plotter", required=True, help="real plotter IP")
    p.add_argument("--port", type=int, default=51200)
    p.add_argument("--name", default="Helm (proxy)", help="name shown on the phone")
    p.set_defaults(func=cmd_mitm)

    p = sub.add_parser("pair", help="register this client with the plotter and get a role/token")
    p.add_argument("--host", help="bl-id service IP (default: auto-discover)")
    p.add_argument("--port", type=int, help="bl-id service port (default 80)")
    p.add_argument("--role", default="guest", choices=["guest", "owner", "dealer"],
                   help="role to request (default: guest)")
    p.add_argument("--reset", action="store_true",
                   help="forget the saved identity (re-register next time)")
    p.add_argument("--list", action="store_true",
                   help="list registered bl-ids/users on the plotter")
    p.set_defaults(func=cmd_pair)

    p = sub.add_parser("connect", help="experimental: probe the GMN2 Helm session (:51200)")
    p.add_argument("--host", default="172.16.6.0")
    p.add_argument("--port", type=int, default=51200)
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("helm", help="open the Helm session + play video (main command)")
    p.add_argument("--host", help="plotter IP (default: auto-discover)")
    p.add_argument("--tap", nargs=2, type=float, metavar=("X", "Y"),
                   help="send a test tap at normalized 0..1 coords, then play")
    p.add_argument("--no-video", action="store_true", help="session only, no player")
    p.set_defaults(func=cmd_helm)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
