#!/usr/bin/env python3
"""vh_tunnel_exec.py - decisive test: does the VH tunnel execute control messages?

Hypothesis: VH payloads are control-protocol frames routed by the hub
(PC=0 <-> Base=1 <-> Head=2). Send WELL-FORMED harmless messages and
watch for replies coming back on the VH socket:
  T1 Setup{Query=true}        (protobuf 144, read-only)
  T2 RequestStatus->BaseStatus (plain dialect, read-only)
  T3 SoftwareVersion          (plain dialect, read-only)
  T4 Configuration read       (protobuf 145, read-only)
  T5 RequestStatus->HeadStatus addressed to Head(2)
Each case on a fresh connection; decode anything that comes back.
"""
import socket, struct, sys, time, datetime

HOST = "192.168.3.1"; VH_PORT = 7575

HELLO = bytes(30) + b"\x84\x00\x00\x00" + b"vh (host)".ljust(76, b"\x00") \
        + b"vhhost".ljust(51, b"\x00") + b"\x06\x00\x03\x00"

def env_a(payload):
    return struct.pack(">I", 0) + struct.pack("<I", len(payload)) + payload

def pkt(src, dst, seq, opts, payload=b""):
    return struct.pack(">BBIBH", src, dst, seq, opts, len(payload)) + payload

def msg(tag, t, body=b""):
    return struct.pack(">HH", tag, t) + body

def wrap(ctype, payload):
    return bytes([1]) + struct.pack(">H", ctype) + payload

def now():
    return datetime.datetime.now().strftime("%H:%M:%S")

def port_up(t=1.5):
    try:
        s = socket.create_connection((HOST, VH_PORT), timeout=t)
        s.close(); return True
    except OSError:
        return False

def wait_port(timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if port_up(): return True
        time.sleep(2)
    return False

def drain(s, t=1.2):
    buf = b""
    end = time.time() + t
    while time.time() < end:
        try:
            d = s.recv(65536)
            if not d: break
            buf += d
            end = time.time() + 0.5
        except socket.timeout:
            break
    return buf

def show(buf, label):
    """Decode VH envelopes; if a payload parses as a control frame, show it."""
    while len(buf) >= 8:
        z = struct.unpack_from(">I", buf, 0)[0]
        ln = struct.unpack_from("<I", buf, 4)[0]
        if z != 0:
            print(f"  {label}: non-A envelope {buf[:24].hex()}")
            return
        if 8 + ln > len(buf):
            if buf:
                print(f"  {label}: pending {len(buf)}B (declared {ln}) {buf[:24].hex()}")
            return
        p = buf[8:8+ln]
        t = struct.unpack_from("<I", p, 0)[0] if ln >= 4 else -1
        body = p[4:]
        desc = f"type={t} len={ln} body={body[:40].hex()}"
        # try control-frame parse of the payload
        if ln >= 9:
            src, dst = p[0], p[1]
            seq = struct.unpack_from(">I", p, 2)[0]
            opts = p[6]
            mlen = struct.unpack_from(">H", p, 7)[0]
            mtag, mtype = struct.unpack_from(">HH", p, 9)
            desc += (f" | CTRL src={src} dst={dst} seq={seq} opts={opts} "
                     f"mlen={mlen} tag=0x{mtag:04x} mtype={mtype} "
                     f"mbody={p[13:13+mlen][:32].hex()}")
        print(f"  {label}: {desc}")
        buf = buf[8+ln:]

def run_case(name, frame):
    print(f"[{now()}] === {name}: frame={frame.hex()}")
    if not wait_port(20):
        print("  PORT DOWN, abort"); return False
    s = socket.create_connection((HOST, VH_PORT), timeout=2)
    s.settimeout(2)
    try:
        drain(s, 1.0)
        s.sendall(env_a(struct.pack("<I", 0) + HELLO))
        drain(s, 1.2)
        s.sendall(env_a(frame))
        r = drain(s, 3.5)
        if r:
            show(r, f"{name} reply")
        else:
            print("  (no reply on VH socket)")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"  RST: {e}")
    finally:
        try: s.close()
        except Exception: pass
    time.sleep(1.5)
    return True

def main():
    cases = []
    # T1: Setup{Query=true} -> protobuf 144, field 14 varint 1
    cases.append(("T1-SetupQuery->Base",
                  pkt(0, 1, 0, 3, msg(0x4002, 140, wrap(144, b"\x70\x01")))))
    # T2: RequestStatus -> BaseStatus (plain dialect)
    cases.append(("T2-RequestStatus->Base",
                  pkt(0, 1, 1, 3, msg(0x4002, 128, struct.pack(">H", 129)))))
    # T3: SoftwareVersion
    cases.append(("T3-SoftwareVersion->Base",
                  pkt(0, 1, 2, 3, msg(0x4002, 134, b""))))
    # T4: Configuration read (protobuf 145, empty)
    cases.append(("T4-Configuration->Base",
                  pkt(0, 1, 3, 3, msg(0x4002, 140, wrap(145, b"")))))
    # T5: HeadStatus request addressed to the Head
    cases.append(("T5-HeadStatus->Head",
                  pkt(0, 2, 4, 3, msg(0x4002, 128, struct.pack(">H", 130)))))
    for name, frame in cases:
        if not run_case(name, frame):
            return 1
    print("[*] done - fetch report to see what the base logged")
    return 0

if __name__ == "__main__":
    sys.exit(main())
