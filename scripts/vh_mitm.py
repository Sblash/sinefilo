#!/usr/bin/env python3
"""vh_mitm.py - MITM proxy for VirtualHere client<->server protocol capture.

client -> 127.0.0.1:LISTEN -> real server (FORWARD port)
Both directions logged with message framing decoded:
    [u32 zero][u32 LE len][payload]  payload[0:4] = type

Raw bytes appended to /tmp/vh_mitm_raw.bin between ===DIR/MSG-END=== markers.
"""
import socket, struct, sys, threading, time

LISTEN = int(sys.argv[1]) if len(sys.argv) > 1 else 7575
if len(sys.argv) > 2 and ":" in sys.argv[2]:
    FHOST, _, FPORT = sys.argv[2].rpartition(":")
    FORWARD = int(FPORT)
else:
    FHOST = "127.0.0.1"
    FORWARD = int(sys.argv[2]) if len(sys.argv) > 2 else 7576

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def raw_dump(tag, data):
    with open("/tmp/vh_mitm_raw.bin", "ab") as f:
        f.write(f"==={tag}===\n".encode() + data + b"\n==MSG-END===\n")

def relay(src, dst, tag):
    buf = b""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                log(f"{tag}: closed")
                break
            raw_dump(tag, data)
            buf += data
            # decode complete messages
            while len(buf) >= 8:
                z = struct.unpack_from(">I", buf, 0)[0]
                ln = struct.unpack_from("<I", buf, 4)[0]
                if z != 0:
                    log(f"{tag}: DESYNC u32={z:#x} — {buf[:16].hex()}")
                    buf = b""
                    break
                if 8 + ln > len(buf):
                    break
                payload = buf[8:8+ln]
                t = struct.unpack_from("<I", payload, 0)[0] if ln >= 4 else -1
                txt = b"".join(bytes([b]) if 32 <= b < 127 else b"." for b in payload[:48]).decode()
                log(f"{tag} type={t:2} len={ln:4} {payload[:16].hex()} |{txt}|")
                buf = buf[8+ln:]
            dst.sendall(data)
    except OSError as e:
        log(f"{tag}: error {e}")
    finally:
        try: src.close()
        except Exception: pass
        try: dst.close()
        except Exception: pass

def handle(client):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.connect((FHOST, FORWARD))
    except OSError as e:
        log(f"cannot reach real server on {FORWARD}: {e}")
        client.close()
        return
    t1 = threading.Thread(target=relay, args=(client, server, "C->S"), daemon=True)
    t2 = threading.Thread(target=relay, args=(server, client, "S->C"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN))
    srv.listen(4)
    log(f"MITM proxy on {LISTEN} -> real server on {FORWARD}")
    while True:
        conn, addr = srv.accept()
        log(f"client connected: {addr}")
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
