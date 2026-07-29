"""Standalone verification for HelmClient's keepalive — no plotter needed.

Runs a minimal fake TCP server that speaks just enough of the protocol to
grant a touch context, then checks that HelmClient re-sends
KEEPALIVE_SUBSCRIBE_INDICES via T_SUBSCRIBE every KEEPALIVE_INTERVAL seconds,
and never sends a synthetic T_TOUCH (the earlier, reverted approach — see the
helm_client module docstring for why it was replaced).

    python3 -m helm.keepalive_test
"""

from __future__ import annotations

import socket
import struct
import threading
import time

from helm.helm_client import (
    HelmClient,
    KEEPALIVE_SUBSCRIBE_INDICES,
    MAGIC,
    SUBSCRIBE_INDICES,
    T_ACQUIRE,
    T_CONTEXT,
    T_SUBSCRIBE,
    T_TOUCH,
    parse_frames,
)

GRANTED_CTX = bytes([0x01, 0x02, 0x03, 0x04])


def _run_fake_server(server_sock: socket.socket, received: list[tuple[int, bytes]]) -> None:
    conn, _ = server_sock.accept()
    conn.settimeout(15)
    buf = bytearray()
    try:
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
            consumed = 0
            for mtype, payload in parse_frames(bytes(buf)):
                consumed += 8 + len(payload)
                received.append((mtype, payload))
                if mtype == T_ACQUIRE:
                    reply = struct.pack("<HHI", T_CONTEXT, MAGIC, 8)
                    reply += struct.pack("<I", 1) + GRANTED_CTX
                    conn.sendall(reply)
            del buf[:consumed]
    finally:
        conn.close()


def main() -> int:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    received: list[tuple[int, bytes]] = []
    server_thread = threading.Thread(target=_run_fake_server, args=(server_sock, received))
    server_thread.start()

    client = HelmClient("127.0.0.1", port=port)
    client.connect(timeout=2.0)
    assert client.touch_ctx == GRANTED_CTX, f"handshake failed: touch_ctx={client.touch_ctx}"
    print("handshake ok, touch context granted")

    frames_after_handshake = len(received)  # includes the T_ACQUIRE frame too
    subscribes_after_handshake = sum(1 for t, _ in received if t == T_SUBSCRIBE)
    assert subscribes_after_handshake == len(SUBSCRIBE_INDICES), (
        f"expected {len(SUBSCRIBE_INDICES)} subscribes from the handshake itself, "
        f"got {subscribes_after_handshake}"
    )

    print("waiting ~10.5s for two keepalive ticks...")
    time.sleep(10.5)

    new_subscribes = [
        struct.unpack("<I", pl)[0]
        for t, pl in received[frames_after_handshake:]
        if t == T_SUBSCRIBE
    ]
    touches = [pl for t, pl in received if t == T_TOUCH]

    client.close()
    server_sock.close()
    server_thread.join(timeout=1)

    assert len(touches) == 0, f"keepalive must never send T_TOUCH, got {len(touches)}"
    assert len(new_subscribes) >= 2 * len(KEEPALIVE_SUBSCRIBE_INDICES), (
        f"expected at least 2 keepalive ticks ({2 * len(KEEPALIVE_SUBSCRIBE_INDICES)} indices), "
        f"got {new_subscribes}"
    )
    for i in range(0, len(new_subscribes) - len(KEEPALIVE_SUBSCRIBE_INDICES) + 1,
                   len(KEEPALIVE_SUBSCRIBE_INDICES)):
        tick = new_subscribes[i:i + len(KEEPALIVE_SUBSCRIBE_INDICES)]
        assert tick == KEEPALIVE_SUBSCRIBE_INDICES, (
            f"keepalive tick indices {tick} != {KEEPALIVE_SUBSCRIBE_INDICES}"
        )

    print(f"ok: {len(new_subscribes) // len(KEEPALIVE_SUBSCRIBE_INDICES)} keepalive tick(s), "
          f"each re-subscribing {KEEPALIVE_SUBSCRIBE_INDICES}, zero synthetic touches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
