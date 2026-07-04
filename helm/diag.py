"""One-shot Helm control diagnostic — run on the plotter's Wi-Fi, share the log.

Because the laptop can't be on the plotter's Wi-Fi and the internet at once,
this captures everything needed to debug control in a single run and writes it
to helm-diag.log. It:
  * opens the session (handshake incl. the 0x1644 acquire),
  * logs every frame the plotter sends back (device info / control status),
  * sends taps at several screen positions with pauses,
  * logs anything the plotter returns after each tap.

Watch the plotter screen while it runs and note whether anything reacts.
"""

from __future__ import annotations

import sys
import time

from . import gmn2
from .helm_client import HelmClient, _frame, T_TOUCH, encode_touch


def _dump(log, tag, data):
    log.write(f"\n[{tag}] {len(data)} bytes\n")
    if not data:
        return
    frames = list(gmn2.parse_helm_frames(data))
    from collections import Counter
    log.write("  types: " + str(dict(Counter(t for t, _ in frames))) + "\n")
    for typ, pl in frames[:30]:
        ap = "".join(chr(b) if 32 <= b < 127 else "." for b in pl[:48])
        log.write(f"  0x{typ:04x} len={len(pl):<5} {pl[:48].hex()}  {ap}\n")


def run(host: str = "172.16.6.0", out: str = "helm-diag.log") -> int:
    log = open(out, "w")
    def p(*a):
        s = " ".join(str(x) for x in a)
        print(s); log.write(s + "\n"); log.flush()

    p(f"connecting {host}:51200")
    c = HelmClient(host)
    try:
        c.connect()
    except OSError as e:
        p(f"connect failed: {e}")
        return 1
    p("handshake sent (hello, token, subscribes, acquire)")
    if c.touch_ctx:
        p(f"touch context assigned by plotter: {c.touch_ctx.hex()}  ✓ control enabled")
    else:
        p("NO touch context (0x1645) received — control will NOT work. "
          "Check App-permission = View and Control.")
    time.sleep(0.6)
    _dump(log, "handshake-response", c.read(32768, timeout=2.0))

    # taps at center, then the four quadrants, with pauses so you can watch.
    spots = [("center", 0.5, 0.5), ("top-left", 0.2, 0.2),
             ("top-right", 0.8, 0.2), ("bottom-left", 0.2, 0.8),
             ("bottom-right", 0.8, 0.8)]
    for name, x, y in spots:
        p(f"\n>>> TAP {name} ({x},{y}) — watch the plotter")
        c.tap(x, y)
        time.sleep(1.2)
        _dump(log, f"after-tap-{name}", c.read(8192, timeout=1.0))

    # a slow drag across the middle (pan gesture)
    p("\n>>> DRAG left->right across middle — watch the plotter")
    c.drag([(0.2, 0.5), (0.35, 0.5), (0.5, 0.5), (0.65, 0.5), (0.8, 0.5)],
           step_delay=0.15)
    time.sleep(1.0)
    _dump(log, "after-drag", c.read(8192, timeout=1.0))

    c.close()
    p(f"\nDone. Share {out} and say whether the plotter reacted to anything.")
    log.close()
    return 0


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "172.16.6.0"
    raise SystemExit(run(host))
