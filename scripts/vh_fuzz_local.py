#!/usr/bin/env python3
"""vh_fuzz_local.py - structured fuzz of the VirtualHere server parser.

Target: local official vhusbd64u v4.8.8 (same protocol lineage as the
nofio base's server). One TCP session per case; server liveness checked
after every case; on crash the case is saved and the server restarted.

Stages:
  E: envelope framing fuzz (no handshake) - len/reserved mutations
  H: hello mutations (truncations, overlengths, flag/version fields)
  T: type-field fuzz after a valid hello (types 0..1023, fixed bodies)
  S: stateful fuzz (hello -> enum -> type/body mutations, big bodies,
     mid-stream desync)
"""
import os, random, signal, socket, struct, subprocess, sys, time

SRV = "/tmp/vhusbd64u"
CFGDIR = "/tmp/vh_fuzz_srv"
PORT = 7575
CASES_DIR = "/tmp/vh_fuzz_crashes"
os.makedirs(CFGDIR, exist_ok=True)
os.makedirs(CASES_DIR, exist_ok=True)

random.seed(20261013)

HELLO = bytes(30) + b"\x84\x00\x00\x00" + b"fuzz (fuzzbox)".ljust(76, b"\x00") \
        + b"fuzzbox".ljust(51, b"\x00") + b"\x06\x00\x03\x00"
assert len(HELLO) == 165
ENUM = struct.pack("<I", 9) + bytes(29)
PING = struct.pack("<I", 10) + bytes(29)
HB = struct.pack("<I", 15) + b"\x04\x00\x00\x00" + struct.pack("<I", 0x6ACE338F) + bytes(20)

def env_a(payload, reserved=0, declen=None):
    n = len(payload) if declen is None else declen
    return struct.pack(">I", reserved) + struct.pack("<I", n) + payload

def type_msg(t, body=b""):
    return env_a(struct.pack("<I", t) + body)

# ---------------------------------------------------------------- server ----
server_proc = None

def start_server():
    global server_proc
    subprocess.run(["sudo", "-n", "killall", "-9", "vhusbd64u"],
                   capture_output=True)
    for _ in range(20):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=0.3)
            s.close(); time.sleep(0.1)
        except OSError:
            break
    cfg = os.path.join(CFGDIR, "config.ini")
    if not os.path.exists(cfg):
        open(cfg, "w").write("")
    server_proc = subprocess.Popen(
        ["sudo", "-n", SRV, "-c", cfg],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid)
    # wait for the port
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False

def server_alive():
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False

def stop_server():
    global server_proc
    if server_proc:
        try:
            subprocess.run(["sudo", "-n", "killall", "-9", "vhusbd64u"], capture_output=True)
        except Exception:
            pass
        server_proc = None

# ----------------------------------------------------------------- cases ----
def gen_cases():
    cases = []

    # -- E: envelope fuzz, no handshake
    for ln in (0, 1, 2, 3, 4, 5, 8, 31, 32, 33, 164, 165, 166, 511, 65535,
               0xFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF):
        cases.append(("E-len%d" % ln,
                      [struct.pack(">I", 0) + struct.pack("<I", ln) + b"\x00" * 40]))
    for res in (1, 0xFF, 0x80000000, 0xFFFFFFFF, 0x00010000):
        cases.append(("E-res%#x" % res,
                      [struct.pack(">I", res) + struct.pack("<I", 165) + HELLO]))
    # declared longer than provided (partial message then nothing)
    for ln in (170, 1000, 70000, 0xFFFFFF):
        cases.append(("E-short%d" % ln,
                      [struct.pack(">I", 0) + struct.pack("<I", ln) + HELLO]))
    # envelope B style to an A server
    cases.append(("E-bstyle", [struct.pack("<I", 143) + struct.pack("<I", 757) + b"\x2f" * 143]))

    # -- H: hello mutations
    for cut in (4, 8, 16, 30, 34, 50, 100, 110, 160, 164):
        cases.append(("H-cut%d" % cut, [type_msg(0, HELLO[:cut])]))
    for extra in (1, 4, 100, 5000, 60000):
        h = HELLO + b"\x41" * extra
        cases.append(("H-long%d" % extra, [type_msg(0, h)]))
    # fill the string fields completely (no null padding)
    h = bytes(30) + b"\xff\xff\xff\xff" + b"U" * 76 + b"H" * 51 + b"\xff" * 4
    cases.append(("H-nofill", [type_msg(0, h)]))
    # flag word mutations at offset 30
    for fl in (0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x000000FF, 0x0000FFFF):
        h = HELLO[:30] + struct.pack("<I", fl) + HELLO[34:]
        cases.append(("H-flag%#x" % fl, [type_msg(0, h)]))
    # version tail mutations
    for v in (b"\xff" * 4, b"\x00" * 4, b"\x63\x00\x00\x00", b"\x0a\x00\x09\x00"):
        h = HELLO[:-4] + v
        cases.append(("H-ver" + v.hex(), [type_msg(0, h)]))
    # declared len != actual for the hello
    cases.append(("H-declen+8", [env_a(struct.pack("<I", 0) + HELLO, declen=173)]))
    cases.append(("H-declen-8", [env_a(struct.pack("<I", 0) + HELLO[:157], declen=165)]))

    # -- T: type fuzz after a valid hello
    for t in list(range(0, 65)) + [100, 200, 300, 500, 604, 757, 1023, 0xFFFF]:
        cases.append(("T-type%d" % t,
                      [type_msg(0, HELLO), type_msg(t, b"\x00" * 29)]))
    # type fuzz with bigger bodies
    for t in (1, 2, 5, 9, 16, 24, 604):
        cases.append(("T-big%d" % t,
                      [type_msg(0, HELLO), type_msg(t, bytes(random.getrandbits(8) for _ in range(600)))]))
    # type fuzz with string-bearing bodies (overlong strings, no nulls)
    for t in (1, 2, 3, 5, 9, 20, 604):
        cases.append(("T-str%d" % t,
                      [type_msg(0, HELLO), type_msg(t, b"S" * 600)]))

    # -- S: stateful sequences
    # enum then mutated types (the "use" flow lives somewhere past enum)
    for t in range(11, 40):
        cases.append(("S-enum-then-%d" % t,
                      [type_msg(0, HELLO), type_msg(9, b"\x00" * 29),
                       type_msg(t, b"\x00" * 29)]))
    # enum with junk body
    for body in (b"\x01" * 29, b"\xff" * 29, struct.pack("<I", 0xFFFF) + b"\x00" * 25,
                 struct.pack("<I", 16) + b"A" * 25):
        cases.append(("S-enum-" + body[:4].hex(),
                      [type_msg(0, HELLO), type_msg(9, body)]))
    # device-use guesses: strings that look like device addresses
    for addr in (b"1-1", b"1-1.1", b"2-1", b"1-2.3.4", b"LHR-1C2256EF",
                 b"1-1\x00" + b"\x00" * 25, b"A" * 100):
        cases.append(("S-use-" + addr[:6].hex(),
                      [type_msg(0, HELLO), type_msg(9, b"\x00" * 29),
                       type_msg(9, addr.ljust(29, b"\x00"))]))
    # ping/heartbeat body junk
    for t, body in ((10, b"\xff" * 29), (10, struct.pack("<I", 0xFFFF) + b"\x00" * 25),
                    (15, b"\xff" * 33), (15, b"\x04\x00\x00\x00" + b"\xff" * 4 + b"\x00" * 20)):
        cases.append(("S-junk-%d-%s" % (t, body[:4].hex()),
                      [type_msg(0, HELLO), type_msg(t, body)]))
    # mid-stream desync after valid hello
    cases.append(("S-desync", [type_msg(0, HELLO),
                               struct.pack(">I", 0xDEAD) + struct.pack("<I", 100) + b"\x00" * 100]))
    # rapid-fire concat
    cases.append(("S-concat", [type_msg(0, HELLO) + type_msg(9, b"\x00" * 29) +
                               type_msg(10, b"\x00" * 29) * 5]))
    # huge single body post-hello
    cases.append(("S-huge", [type_msg(0, HELLO),
                             env_a(struct.pack("<I", 9) + b"\x00" * 100000)]))
    return cases

def run_case(name, msgs, timeout=0.6):
    """Returns (result, detail). result in ok/closed/reset/timeout/dead"""
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=1)
    except OSError as e:
        return "dead", f"connect: {e}"
    s.settimeout(timeout)
    got = b""
    try:
        for m in msgs:
            s.sendall(m)
        end = time.time() + timeout
        while time.time() < end:
            try:
                d = s.recv(65536)
                if not d:
                    return "closed", f"reply={len(got)}B"
                got += d
            except socket.timeout:
                break
    except (ConnectionResetError, BrokenPipeError) as e:
        if not server_alive():
            return "dead", f"reset, server died, reply={len(got)}B"
        return "reset", f"{e}, reply={len(got)}B"
    finally:
        try: s.close()
        except Exception: pass
    if not server_alive():
        return "dead", f"server died after, reply={len(got)}B"
    return "ok", f"reply={len(got)}B"

def main():
    if not start_server():
        print("[-] could not start local server"); return 1
    print("[*] local vhusbd64u started on 127.0.0.1:%d" % PORT)
    cases = gen_cases()
    print(f"[*] {len(cases)} cases")
    crashes = 0
    try:
        for i, (name, msgs) in enumerate(cases):
            res, detail = run_case(name, msgs)
            flag = ""
            if res == "dead":
                crashes += 1
                flag = "  <<<< CRASH"
                fn = os.path.join(CASES_DIR, f"{crashes:03d}_{name}.bin")
                with open(fn, "wb") as f:
                    for m in msgs:
                        f.write(m)
                with open(fn + ".txt", "w") as f:
                    f.write(f"{name}\n{res}: {detail}\n")
                stop_server()
                time.sleep(0.5)
                if not start_server():
                    print(f"[!] server did not restart after case {name}")
                    return 1
            print(f"{i:4} {name:24} -> {res:8} {detail}{flag}")
    finally:
        stop_server()
    print(f"[*] done: {crashes} crashes in {len(cases)} cases")
    return 0

if __name__ == "__main__":
    sys.exit(main())
