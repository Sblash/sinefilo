#!/usr/bin/env python3
"""vh_fuzz_base.py - run the structured VH corpus against the nofio base.

Reuses gen_cases() from the local fuzzer (same corpus). Target:
192.168.3.1:7575 (the base's VirtualHere server, paired state).
Crash oracle: TCP connect to 7575 (and control 34566) after each case.
NO restart capability - on death we stop and report. Baseline-relevant
extra cases: the base dialect's own types (1 = hub desc, 16 = records)
sent client->server.

If the base's VH server dies: VR streaming breaks; it is presumably
respawned by imr_controller/systemd, or recoverable via Setup.Reboot.
"""
import socket, struct, sys, time

sys.path.insert(0, "/tmp")
import importlib.util
spec = importlib.util.spec_from_file_location("vfl", "/tmp/vh_fuzz_local.py")
vfl = importlib.util.module_from_spec(spec)
# prevent the module's main() from running: it only runs under __main__
spec.loader.exec_module(vfl)

HOST = "192.168.3.1"
VH_PORT = 7575
CTRL_PORT = 34566

def extra_cases():
    cases = []
    # the base's own dialect types, client->server
    for t in (1, 16, 12, 11, 24):
        cases.append(("B-dialect%d" % t,
                      [vfl.type_msg(0, vfl.HELLO), vfl.type_msg(t, b"\x00" * 29)]))
    # hello then immediately the enum then hub-desc-shaped garbage
    hub_garbage = b"\x00" * 8 + b"\x2f\x01\x00\x00" + b"G" * 300
    cases.append(("B-hubgarbage", [vfl.type_msg(0, vfl.HELLO),
                                  vfl.type_msg(1, hub_garbage)]))
    # repeated hello flood in one connection
    cases.append(("B-helloflood", [vfl.type_msg(0, vfl.HELLO) * 50]))
    return cases

def port_open(host, port, timeout=1.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False

def run_case(name, msgs, timeout=1.0):
    try:
        s = socket.create_connection((HOST, VH_PORT), timeout=2)
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
        return "reset", f"{e}, reply={len(got)}B"
    finally:
        try: s.close()
        except Exception: pass
    if not port_open(HOST, VH_PORT):
        return "dead", f"7575 down after, reply={len(got)}B"
    return "ok", f"reply={len(got)}B"

def main():
    if not port_open(HOST, VH_PORT):
        print("[-] base 7575 not reachable"); return 1
    if not port_open(HOST, CTRL_PORT):
        print("[!] control 34566 not reachable (continuing)")
    cases = vfl.gen_cases() + extra_cases()
    print(f"[*] {len(cases)} cases against {HOST}:{VH_PORT}")
    anomalies = []
    try:
        for i, (name, msgs) in enumerate(cases):
            res, detail = run_case(name, msgs)
            flag = ""
            if res == "dead":
                flag = "  <<<< SERVER DOWN"
                anomalies.append((name, res, detail))
                ctrl = port_open(HOST, CTRL_PORT)
                print(f"{i:4} {name:24} -> {res:8} {detail}{flag} "
                      f"(control 34566 {'UP' if ctrl else 'DOWN'})")
                # give it a moment in case it respawns
                for _ in range(10):
                    if port_open(HOST, VH_PORT):
                        print("[*] 7575 came back (respawned)")
                        break
                    time.sleep(1)
                else:
                    print("[*] 7575 stayed down - stopping campaign")
                    break
            elif res in ("reset", "closed"):
                flag = "  (anom)" if res == "reset" else ""
                if res == "reset":
                    anomalies.append((name, res, detail))
            print(f"{i:4} {name:24} -> {res:8} {detail}{flag}", flush=True)
            time.sleep(0.15)
    finally:
        ctrl = port_open(HOST, CTRL_PORT)
        vh = port_open(HOST, VH_PORT)
        print(f"[*] final state: 7575 {'UP' if vh else 'DOWN'}, "
              f"34566 {'UP' if ctrl else 'DOWN'}")
    print(f"[*] anomalies: {len(anomalies)}")
    for a in anomalies:
        print(f"    {a}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
