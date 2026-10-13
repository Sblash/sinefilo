#!/usr/bin/env python3
"""vh_mitm_translate.py - MITM client<->nofio-base with dialect translation.

The nofio base's hub speaks an old dialect (hub description type=1, no
license banner) that client 6.0.3 parses only partially (hub name shows,
devices do not nest, USE unavailable). vh_mock3 proved the client accepts
the nofio type-16 device records when the hub description is in the
modern dialect. This proxy rewrites the base's type-1 hub description
into the captured official (v4.8.8) hub description + license banner,
and passes everything else through unchanged.

Usage: vh_mitm_translate.py <listen_port> <forward_host:port>
Dumps both directions raw to /tmp/vh_useflow.bin with direction markers.
"""
import socket, struct, sys, threading, time

LISTEN = int(sys.argv[1]) if len(sys.argv) > 1 else 7576
if len(sys.argv) > 2 and ":" in sys.argv[2]:
    FHOST, _, FPORT = sys.argv[2].rpartition(":")
    FORWARD = int(FPORT)
else:
    FHOST, FORWARD = "127.0.0.1", int(sys.argv[2]) if len(sys.argv) > 2 else 7575

RAW = "/tmp/vh_useflow.bin"

def load_capture(path="/tmp/vh_mitm_raw.bin"):
    raw = open(path, "rb").read()
    chunks = []
    for c in raw.split(b"\n==MSG-END===\n"):
        if c.startswith(b"===S->C===\n"):
            chunks.append(c[len(b"===S->C===\n"):])
    return chunks

def build_hello_reply():
    """Official v4.8.8 hub description (envelope B type 757) + license(24)."""
    hello_reply = b""
    for ch in load_capture():
        i = 0
        while i + 8 <= len(ch):
            be0 = struct.unpack_from(">I", ch, i)[0]
            le_len = struct.unpack_from("<I", ch, i + 4)[0]
            if be0 == 0 and 8 + le_len <= len(ch) - i and le_len >= 4:
                m = ch[i:i+8+le_len]
                t = struct.unpack_from("<I", m, 8)[0]
                if t == 24:
                    hello_reply += m
                i += 8 + le_len
                continue
            le_len2, le_type = struct.unpack_from("<II", ch, i)
            if 8 + le_len2 <= len(ch) - i and le_len2 >= 4:
                m = ch[i:i+8+le_len2]
                if le_type == 757:
                    hello_reply += m
                i += 8 + le_len2
                continue
            break
    return hello_reply

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def raw_dump(tag, data):
    with open(RAW, "ab") as f:
        f.write(f"==={tag}===\n".encode() + data + b"\n==MSG-END===\n")

def split_messages(buf):
    """Yield (envelope, type, message_bytes) for both dialects."""
    out = []
    i = 0
    while i + 8 <= len(buf):
        be0 = struct.unpack_from(">I", buf, i)[0]
        le_len = struct.unpack_from("<I", buf, i + 4)[0]
        if be0 == 0 and le_len >= 4 and 8 + le_len <= len(buf) - i:
            t = struct.unpack_from("<I", buf, i + 8)[0]
            out.append(("std", t, buf[i:i+8+le_len]))
            i += 8 + le_len
            continue
        le_len2, le_type = struct.unpack_from("<II", buf, i)
        if le_len2 >= 4 and 8 + le_len2 <= len(buf) - i and le_type < 0x10000:
            out.append(("new", le_type, buf[i:i+8+le_len2]))
            i += 8 + le_len2
            continue
        break
    return out, buf[i:]

def handle(client):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect((FHOST, FORWARD))
    except OSError as e:
        log(f"cannot reach real server {FHOST}:{FORWARD}: {e}")
        client.close(); return

    hello_reply = build_hello_reply()
    log(f"hello-reply translation ready: {len(hello_reply)}B")

    def c2s():
        buf = b""
        try:
            while True:
                d = client.recv(65536)
                if not d: break
                raw_dump("C->S", d)
                server.sendall(d)
        except OSError: pass
        finally:
            try: server.close()
            except Exception: pass

    def s2c():
        buf = b""
        translated = False
        try:
            while True:
                d = server.recv(65536)
                if not d: break
                raw_dump("S->C", d)
                buf += d
                msgs, buf = split_messages(buf)
                for env, t, m in msgs:
                    if env == "std" and t == 1 and not translated:
                        # base's old-dialect hub description -> modern one
                        log(f"translating type-1 hub desc ({len(m)}B) "
                            f"-> official {len(hello_reply)}B")
                        client.sendall(hello_reply)
                        translated = True
                    else:
                        client.sendall(m)
        except OSError: pass
        finally:
            try: client.close()
            except Exception: pass

    threading.Thread(target=c2s, daemon=True).start()
    s2c()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN))
    srv.listen(8)
    log(f"MITM+translate on {LISTEN} -> {FHOST}:{FORWARD}")
    while True:
        conn, addr = srv.accept()
        log(f"client connected: {addr}")
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
