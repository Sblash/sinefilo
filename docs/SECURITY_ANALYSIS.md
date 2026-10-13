# Security Analysis — TCP/IP attack surface of the Nofio base

*Date: October 7, 2026 (passive analysis) — updated October 7, 2026 (active assessment)*
*Scope: vulnerability analysis of the Nofio base station reachable over its
USB network (192.168.3.0/24), with a focus on RCE potential.*

> **Rules of engagement:** the October 7 passive pass used read-only
> operations only. The same-day **active assessment** was explicitly
> authorized by the owner (their own hardware): protocol fuzzing
> (~110 cases), head-impersonation handshakes, update-staging probes (never
> sending `SoftwareUpdateComplete` with a valid image, never flashing), one
> `Setup.Reboot`, and a raw-USB PoC of the kernel NCM gadget bug. Device
> state was verified healthy after each phase; the only persistent effect
> found (an exhausted `/tmp`) was cleared by the documented reboot.

---

## 0. Headline result — confirmed kernel OOB read (f_ncm, live PoC)

The **CDC-NCM gadget parser of the base's kernel 5.10.0 is confirmed
vulnerable, live, to the `ncm_unwrap_ntb()` `wBlockLength` underflow**
(upstream kernel CVE record CVE-2026-31617; the code at tag v5.10 matches
the pre-fix pattern, verified directly against the source).

Proof (tool: `scripts/ncm_raw.py`, raw libusb host, kernel `cdc_ncm`
driver detached; parser behavior cross-validated by the faithful simulator
`scripts/ncm_unwrap_sim.py`):

1. The raw pipeline works end-to-end: hand-crafted NTB16 → base's
   `usb0` → ICMP echo reply read back from the IN endpoint (ARP answered
   manually; the base had lost its ARP entry after the reboot).
2. A 28-byte NTB with `wBlockLength = 1` and an in-bounds NDP16 whose DPE0
   declares `wDatagramIndex = 5376, wDatagramLength = 1500` passes every
   sanity check in the v5.10 parser — because `block_len - ndp_size`
   (`1 - 8`) and `block_len - dpe_size` (`1 - 4`) **underflow to huge
   unsigned values**, defeating the index bounds checks.
3. `skb_put_data(skb2, skb->data + 5376, 1500)` then copies **~5.3 kB of
   kernel memory beyond the 28-byte skb** into a network frame that is
   delivered to the base's network stack.
4. Observable: after spraying the rx slab with marked ICMP requests, an
   exploit NTB produced a **spurious ICMP echo reply with no matching
   fresh request** — stale kernel rx-buffer content was parsed as an
   ethernet frame and re-injected. Leak channel proven end-to-end.

Impact class: **remote (USB-host) kernel information disclosure** —
arbitrary-index OOB reads within/adjacent to the gadget rx slab, with the
leaked bytes delivered to the network stack. With slab grooming this reads
kernel heap contents beyond the attacker's own data (adjacent freed
objects, pointers → KASLR defeat); the same bug class is the stepping
stone for kernel exploitation. Not a complete RCE on its own: weaponizing
needs a second primitive (the leak alone does not corrupt memory), and no
write primitive was found in the parser (v5.10's copy is read-only).

**NDP32 variant — also proven live.** The gadget's parser is switchable at
runtime by the USB host via the `SET_NTB_FORMAT` class request (0x84, wValue 1
switches `parser_opts` to NDP32 and `ncm->ndp_sign` to `'ncm0'`). With
NTH32/NDP32 framing the same `dwBlockLength = 1` underflow applies, but the
datagram index is now **32-bit** (DPE32), so the OOB read reaches ~4 GB of
index space above `skb->data` instead of NDP16's 64 KB. Verified live: valid
NDP32 NTBs pass (groom echo replies), an in-bounds "canary" DPE is delivered
(proving the exploit NTB is accepted), and OOB-index DPEs re-inject stale
kernel data — spurious ICMP echo replies observed with 32-bit OOB indices
(cases D1/D4/D5 in the session log). The signed `ndp_index` variant of
CVE-2026-74679 (negative 32-bit `dwNdpIndex` reading *below* the buffer) was
validated in the simulator only: the underflowed check rejects offsets in
[-18, -1] but accepts any offset <= -19, so the below-buffer read is
structurally reachable; not exercised on hardware.

---

## 1. Live surface re-verified (2026-10-07)

Base fw v2.5.0, protocol version 80, hw_serial `240104-02E3-NI-b`, connected
over CDC-NCM (`enp0s20f0u3u1`, host address 192.168.3.49). Head off, unpaired.

Full TCP scan (65535 ports, connect scan): identical to the 2026-10-02 map.

| Port | TCP | Service |
|---|---|---|
| 22 | open | `SSH-2.0-dropbear_2019.78` (full kex/algo banner captured) |
| 5355 | open | systemd-resolved (LLMNR/mDNS stack); no data on connect |
| 34566 | open | imr_controller control protocol (waits for client Connect) |
| 34567 | open | head-facing control endpoint; **no data on connect today** (2026-10-02, with the head paired, it immediately pushed `Nak(3)` — today, unpaired, it is silent) |

UDP probe (benign, well-formed packets):

| Port | Probe | Result |
|---|---|---|
| 53 | DNS A queries (root + `imr-nofio1.local` + external names) | **no answer** — dnsmasq does not answer DNS on usb0 (it appears DHCP-only; the host's 192.168.3.49 lease is consistent with dnsmasq@usb0 DHCP) |
| 67 | DHCP discover | no answer (expected: lease already granted / server silent) |
| 123, 161, 1900 | NTP/SNMP/SSDP | no answer |
| 5353 | mDNS `_services._dns-sd._udp.local` enumeration | **answers** — avahi enumerates `_ssh._tcp`, `_sftp-ssh._tcp`, `_imrusb._tcp` (VirtualHere 7575, advertised even while closed) |
| 5355 | LLMNR unicast query | no answer (unicast; LLMNR is normally multicast-only) |
| 44444 | empty datagram | no answer (the video bridge listens on the wireless side, `wi_addr` 10.0.0.1/28, not on usb0) |

Read-only control-protocol session (documented `status`/`state` requests)
worked normally: SoftwareVersion v2.5.0, BaseStatus (CpuTemp 50 °C,
WirelessChannel 13, no bridge).

## 1b. Paired-state surface (2026-10-07, head powered on and paired)

With the wireless link up the base's USB-network surface changes:

| Port | Service | Notes |
|---|---|---|
| 2002 | **NEW: second dropbear 2019.78** | separate instance (different host-key bytes in the KEXINIT), publickey-only (`Permission denied (publickey)`); almost certainly the *head's* SSH relayed by the base over the wireless link |
| 7575 | **NEW: VirtualHere server, ACTIVE** | unauthenticated: on TCP connect it streams the full USB device tree of the paired headset — "Index HMD" (Valve, serial LHR-1C2256EF), "Valve VR Radio" (87C2D0238F-RYB), "Valve VR Radio & HMD Mic" (0DE0AEE388-LYM), "Microchip Tech Hub Controller" — pushed periodically (~4.7 kB / 5 s passive). Device enumeration and serials are readable by any peer on 192.168.3.0/24. Prime new fuzzing/attack target |
| 34567 | head-facing control | with the real head holding the session, a new TCP connection gets the documented `Nak(3)` (AlreadyConnected) pushed on connect (src=Base, dst=Head) |

UDP: unchanged (mDNS only; DNS still not served on usb0; the video bridge
44444 stays on the wireless side). mDNS advertises the same three services
(ssh, sftp-ssh, imrusb/VirtualHere). Full 65535-port TCP scan: exactly
`[22, 2002, 5355, 7575, 34566, 34567]`.

Consequences: the VirtualHere server (proprietary protocol, parses USB
descriptor/ framing from the network peer) is now reachable and is the
largest *new* attack surface; the head's control server is queryable
through base routing (`--target head`, documented in PROTOCOL.md); port
2002 gives the same publickey wall as port 22.

## 1c. VirtualHere (7575) recon (2026-10-07, live server)

- **Unauthenticated advertisement**: any TCP peer on 192.168.3.0/24 receives
  the full USB device tree of the paired headset: 580-byte device records
  (4 per cycle: Index HMD LHR-1C2256EF, Valve VR Radio 87C2D0238F-RYB,
  Valve VR Radio & HMD Mic 0DE0AEE388-LYM, Microchip Hub Controller) plus a
  45-byte keepalive/status message, one cycle (4×580+45 = 2365 B) every ~4 s.
  Records embed raw USB descriptor fragments and length-prefixed strings.
- **Input tolerance**: 15 behavioral probes (single bytes, garbage, length
  prefixes, USB/IP opcodes, text hellos) — the server ignores everything
  and keeps advertising; no reply, no disconnect. It only speaks after the
  correct client handshake (not yet identified).
- **Client binary**: `Resources/vhui64.exe` is **UPX-packed** — unpacks
  cleanly with `upx -d` (29.5 MB unpacked). Strings reveal: embedded
  DTLS/mbedtls stack (SSLReverseLookup support), the client IPC command
  cluster (MANUAL HUB ADD/LIST/REMOVE, AUTO USE *, ADD/LIST/REMOVE REVERSE,
  SERVER RENAME, ONCLIENT, traceMsgs on/off), protocol payload classes
  (LookupStateControl, PortPowerControlPayload), and the vendor build path
  `/media/development/virtualhere/kvmip/HubManager.cpp`.
- No public protocol RE or dissector exists; VirtualHere is a proprietary
  evolution of USB/IP (our probes with USB/IP opcodes got no reaction, so
  the framing diverged).
- Unpacked client kept at /tmp/vhui64_unpacked.exe (session scratch);
  recipe: `upx -d -o out.exe vhui64.exe`.

Next steps for the protocol: disassemble the unpacked client (the network
handler lives around HubManager), or capture a real client-server session
from the original Windows utility, or both.

## 1d. VirtualHere wire format — CRACKED (2026-10-13, mock-server capture)

By running the official Linux client 6.0.3 (needs `vhci_hcd` kernel module,
loaded by the user on the host) against our mock server
(`scripts/vh_mock_server.py`, replaying the advertisement captured from the
base), we captured the client->server side of the protocol (17 messages,
2 connection cycles). Framing confirmed in BOTH directions:

```
[u32 zero/reserved][u32 LE payload_length][payload]
payload[0:4] = u32 LE message_type
```

Evidence: the server's 580-byte device records = 8-byte header + payload
572 (0x23c) with type 16; the server's 45-byte periodic = payload 37; the
client messages decode identically (TCP chunks may concatenate several
messages - a "214B" chunk was actually hello 8+165 followed by keepalive
8+33).

Client message sequence per connection:

| Payload len | Type | Content |
|---|---|---|
| 165 | hello | `0x84` field (flags/version?), **local username and hostname length-prefixed** ("ste (ste)", "matebookxpro") - the client discloses the local user identity to any server it connects to |
| 37 | 15 | status: `04 00 00 00` + **UNIX timestamp LE** (0x6ACE338F = 2026-10-13; increments ~8 s per message) |
| 33 | 10 | keepalive/poll - all zeros, repeated continuously |

The client reconnects and repeats the cycle if the session drops. Device
enumeration was NOT achieved with the plain advertisement replay: the
client accepts the connection, exchanges hello/status/keepalives, but LIST
shows no devices - a hub-description message or correct reply timing is
still missing (next experiment).

Privacy note: any VirtualHere server learns the client machine's username
and hostname upon connection, unauthenticated, before any device use.

## 1e. VirtualHere protocol — FULLY MAPPED + server emulator (2026-10-13)

Method: ran the official Linux client 6.0.3 against the official Linux
server v4.8.8 through an iptables-redirected MITM proxy
(`scripts/vh_mitm.py`), captured the genuine exchange, then rebuilt a full
server emulator (`scripts/vh_mock3.py`) that replays it — and finally fed
it the nofio base's own device records. The client enumerates the nofio
devices from the emulator: full server emulation achieved.

### Wire format (both directions)

```
envelope A (std):  [u32 BE 0][u32 LE len][payload]   payload[0:4] = u32 LE type
envelope B (new):  [u32 LE len][u32 LE type][payload]
```

### Message types

| Dir | Type | Envelope | Meaning |
|---|---|---|---|
| C->S | 0 | A (len 165) | hello: 0x84 flags + local username + local hostname + version tail (6.0.3) — identity disclosure to any server |
| C->S | 9 | A (len 33) | **device-enumeration request** |
| C->S | 10 | A (len 33) | ping |
| C->S | 15 | A (len 37) | status heartbeat (`04 00 00 00` + UNIX ts LE) |
| S->C | =port (e.g. 757) | B | **hub description**: hub name + hub serial ("Desktop Hub" / "20180824-..."; nofio: serial like 240104-02E3-NI-b) + server hostname |
| S->C | 24 | A (len 70) | license banner ("VirtualHere USB Server...") |
| S->C | 604 | B | device record (current dialect) |
| S->C | 16 | A (len 572) | device record (nofio base's dialect — still accepted by client 6.0.3) |
| S->C | 11 | A (len 33) | pong |
| S->C | 12 | A (len 37) | status heartbeat (mirrors/echoes with client's type 15) |

### Genuine connection flow

```
connect
C->S hello(0)          S->C hub-description(type=port, B) + license(24)
C->S ping(10)          S->C pong(11)
C->S enum-request(9)   S->C device records (604/16, one per device)
[steady state: ping(10)/pong(11) every ~3s; heartbeat 12<->15 every ~4s]
```

The nofio base pushes its type-16 advertisement to ANY TCP peer without
this exchange (silent-peer behavior); the enumeration only completes for
a client that performs hello -> 9.

### Artifacts

- `scripts/vh_mitm.py` — bidirectional MITM with live framing decode
- `scripts/vh_mock3.py` — full server emulator; `VH_DEVSRC=nofio` serves
  the base's real type-16 device records (Index HMD, Valve radios, hub)
- `/tmp/vh_mitm_raw.bin` — genuine exchange capture (raw, direction-tagged)
- `/tmp/vh_push.bin` — the nofio base's advertisement capture

### Security relevance

- The unauthenticated advertisement + the identity disclosure in the
  client hello (username/hostname to any server) are now precisely
  characterized.
- The enumeration path (hub-description carries the serial; device records
  carry full USB descriptors) is the data an attacker on 192.168.3.0/24
  can already passively obtain from the base (confirmed live earlier).
- For the nofio-linux goal this is the full server-side protocol needed
  for a native Linux client/server; the remaining unknown is the
  device-USE flow (USB data tunneling after a client attaches a device).

### 1f. Base hub fuzzing campaign (2026-10-13, paired state, live)

Target: the base's VirtualHere hub, reached unauthenticated on TCP 7575.
Corpus: 196 structured cases (envelope/len/hello/type/stateful) first run
locally against official vhusbd64u 4.8.8 (0 crashes, robust baseline),
then against the base. Key findings:

1. **Hub identity**: the VH hub runs *inside* `/usr/bin/imr_controller`
   (journal lines `Hub 1: The interface to the PC(0)/HMD(2) ...`; no
   separate process; killing the hub never touched the 34566 control
   server; two `imr_controller base` processes in the process tree are
   the controller and its helper, both surviving).
2. **Crash surface (DoS, unauthenticated)**: VH envelopes with declared
   payload lengths 5..33 with zero content reset the connection handler
   (RST); a payload `[01][00 81][garbage]` takes the whole listener down
   for a while; ~40 accumulated decode failures leak a resource in the
   process until the support-report generator fails with `Failed to
   open /tmp/support-report.zip` and finally the whole read channel goes
   silent. Recovery: `Setup.Reboot` only. The local 4.8.8 server
   survives all of it.
3. **Mechanism**: graceful. No kernel segfault lines, no systemd
   restarts, stable PID — every kill is a caught C++ exception
   (journald shows `Hub 1: X message decode failed from 0` warnings for
   some inputs). **No memory-corruption evidence anywhere**; the message
   layer is exception-safe, which closes the quick-RCE hope for the hub.
4. **Control-protocol frame parsing inside the hub**: well-formed
   control frames `[src][dst][seq][opts][len]` sent as VH payloads are
   fully parsed by the hub (it echoes seq/opts/len back inside its
   type-1 hub-description reply), but are **not forwarded to the
   control dispatcher** — no execution, no status/version replies, no
   dispatch journal entries. The hub's own protobuf decode attempts
   surface as `SoftwareUpdateComplete message decode failed` warnings
   regardless of content (possibly a vendor logging bug in the
   warning template).
5. **Hello dialect**: the base answers the standard client hello with
   a type-1 hub description (753 B, `IMRNext (2a3613f8c0a2)`, hostname
   `imr-nofio1`, `wlp1s0`), then streams its type-16 device records to
   any peer — full enumeration with zero authentication, version tail
   of client 6.0.3 accepted.
6. Remaining unexplored: the device-USE flow (USB descriptor/URB
   tunneling after a client attaches a device) — the deepest hub parser
   and the classic USB/IP RCE surface. Requires a real-client MITM
   capture against the base (client binary already unpacked at
   `/tmp/vhclient_unpacked`; `vhci_hcd` loads on the host).

Artifacts: `/tmp/vh_fuzz_local.py`, `/tmp/vh_fuzz_base.py`,
`/tmp/vh_char.py`, `/tmp/vh_ctype_probe2.py`, `/tmp/vh_tunnel_exec.py`
(session scratch; the reusable ones are committed under `scripts/`).

## 2. Software inventory (versions confirmed on the device)

| Component | Version | Source |
|---|---|---|
| Kernel | `Linux 5.10.0-nofio` (aarch64, gcc 9.2.1) | support report; **frozen at 5.10.0** — the `linux=release/v2.5.0` tag and the version string show no stable backports (assumption: vendor never merged 5.10.y fixes) |
| OS | Buildroot Linux, systemd initramfs | support report |
| Control server | `/usr/bin/imr_controller base` (C++, custom protocol, ports 34566/34567/34568) | support report; binary not analyzable (OS image AES-eFUSE encrypted) |
| SSH | dropbear 2019.78, `-F -R -s` (publickey only), root login gated on vendor keys (`FINAL_SSH_KEYS=1`) | live banner + support report |
| DNS/DHCP | dnsmasq 2.81 (`dnsmasq@usb0`) | support report |
| mDNS | avahi (version unknown, 2020-era Buildroot) | live enumeration |
| LLMNR/mDNS | systemd-resolved (version unknown; Buildroot ~2020 ⇒ likely systemd 24x) | port 5355 |
| USB gadget | CDC-NCM ⇒ in-kernel `f_ncm` (v5.10 code) | release notes + kernel version |
| USB/IP | VirtualHere server (proprietary binary, version unknown; listens on 7575 only when the head link is up) | live scan + avahi |

## 3. Threat model

- **USB host (the PC)**: by design a *trusted* position — the control
  protocol is unauthenticated (a Connect with the right protocol version is
  enough), and the support report shows the base grants file-transfer
  (update/support-report) channels to it. "Vulnerabilities" from this
  position are mostly by-design unauthenticated access; the security
  boundary that matters is the *signature enforcement* on anything the
  channel can write.
- **Wireless-side attacker**: the base is also an AP
  (`hostapd@wlp1s0`, 10.0.0.0/28; SSID = `hw_serial`, PSK stored in
  `/settings/wi.conf`). A peer that joins this network reaches the same
  listeners (notably the head-facing 34567 and, presumably, dnsmasq on that
  interface). The PSK's derivability from the serial printed on the device
  is an open question (the 16-hex-char PSK observed once could be random
  per-device or derived — one data point, undetermined).
- For this document the analyzed position is the USB host.

## 4. Attack-surface analysis, RCE potential

### 4.1 imr_controller control protocol (TCP 34566, 34567; head 34568) — primary RCE candidate

A custom, unauthenticated, C++ binary server parsing a length-prefixed
binary protocol. The client decoder (decompiled C#, `nofio_probe.py`)
documents the wire format; the server binary is unavailable (encrypted OS
image), so this is an *attack-surface* assessment, not a found bug:

Framing (per packet): `src u8, dst u8, seq u32 BE, options u8 (start/end),
len u16 BE (≤65535)`, then payload chunks reassembled by start/end flags
into messages `tag u16 ((device<<14)|txn), type u16, body`. Messages up to
~4 GB are reassembled across packets.

Memory-corruption-relevant parser paths, as hypotheses to test in a future
*authorized* active session (not tested today):

1. **Chunk reassembly state machine** — start/end flags, u16 lengths and
   the u32 per-source sequence counter are all attacker-controlled at
   connect time (no handshake needed before data). Overlapping
   `start` flags, missing `end`, length/flag mismatches and sequence wraps
   exercise the reassembly buffer management.
2. **SoftwareUpdateData staging** — `SoftwareUpdateMeta{FileType, PacketCount u16, FinalPacketSize u16, FileName ≤255}` followed by
   `SoftwareUpdateData{PacketIndex u16, ≤65523 bytes}` per chunk. A
   server-side staging buffer sized from `PacketCount`/`FinalPacketSize`
   that trusts inconsistent follow-up packets (index > count, duplicate
   index, chunk sizes disagreeing with `final`, more total bytes than
   declared) is the classic embedded overflow primitive. Observed
   behavior so far shows *validation* exists (gaps and wrong file
   types/names are Nak'd), but the coverage of the checks is unknown.
3. **Protobuf wrapper** — type 140: `u8 packet count, u16 content type,
   protobuf bytes`, dispatched by content type into ~30 message schemas.
   Nested, attacker-controlled protobuf with large/deep fields exercises
   the (server-side) protobuf library; parser choice/robustness unknown.
4. **RequestStatus dispatch** — `u16` type used as a dispatch key;
   unknown types are Nak'd (verified), so the table is bounds-checked, at
   least for unknown keys.
5. **Tag/routing** — `tag = (device << 14) | txn` with device ∈ {0..3};
   tags with device bits ≥ 4 or txn > 0x3FFF are trivially craftable and
   were not part of the documented valid space. The base *routes* frames
   by destination across sessions (base↔head), making tag/destination
   confusion (e.g. addressing the head session type on the PC listener)
   an interesting logic-bug area; documented behavior shows the base
   drops mixed sessions, i.e. it does track this.
6. **Unauthenticated write surface** — by design the channel accepts
   firmware upload (`FileType=2` ImrOs) with no protocol-level auth. The
   only barrier to `flash → own the box` is device-side signature
   enforcement (`FINAL_SWUPDATE_KEYS=1`) + secure boot (AES eFUSE +
   RSA-4096 at BootROM). An *unsigned* upload therefore ends at worst in
   a rejected/bricked unit, not RCE — but this makes the updater's
   validation code the single most security-relevant component reachable
   from TCP.

Rating: **highest RCE likelihood on the device** (custom parser,
unauthenticated, C++ target) — but zero public research exists and the
binary is unobtainable for static analysis. Any progress requires active
testing (fuzzing) which was explicitly out of scope today.

### 4.2 Kernel 5.10.0 — CDC-NCM gadget parser (USB host side, adjacent surface)

The base terminates the PC link with the in-kernel `f_ncm` gadget driver.
Reading the v5.10 source of `ncm_unwrap_ntb()`
([f_ncm.c v5.10](https://raw.githubusercontent.com/torvalds/linux/v5.10/drivers/usb/gadget/function/f_ncm.c),
verified locally) shows the pre-fix code for two 2026 upstream kernel-CVE
fixes, both reachable pre-auth by a malicious USB host (i.e. us):

- **`block_len` has no lower bound.** The only check is
  `if (block_len > ntb_max)`. Every subsequent check subtracts from it:
  `ndp_index > (block_len - opts->ndp_size)`,
  `index > block_len - opts->dpe_size`, `index2 > block_len - opts->dpe_size`.
  With `block_len < opts->ndp_size` (e.g. 0–7 for NDP16) the subtraction
  **underflows** and the bounds checks pass for *any* index. The datagram
  copy `skb_put_data(skb2, skb->data + index, dg_len - crc_len)` then reads
  up to `frame_max` (~15 KB, `usb0_mtu` 15300) out of bounds from an
  attacker-directed `index` into a network skb. Upstream fix: *"usb: gadget:
  f_ncm: validate minimum block_len in ncm_unwrap_ntb()"*
  (kernel CVE record **CVE-2026-31617** — kernel heap OOB read / info
  disclosure; the fix description explicitly notes `skb_put_data` copying
  adjacent kernel memory into the network skb).
- **`ndp_index` is `int`** but stores the unsigned `get_ncm()` result; with
  NDP32 a 32-bit `wNdpIndex` > INT_MAX makes it negative, so
  `tmp = (void *)(skb->data + ndp_index)` reads before the buffer while the
  modular/relational checks misbehave. Upstream fix: *"usb: gadget: f_ncm:
  Use unsigned int for ndp_index"* (**CVE-2026-74679**).

Applicability: the vendor kernel is frozen at 5.10.0 (both fixes landed
upstream in 2025/2026), and the v5.10 code matches the pre-fix pattern
exactly (both variants — NDP16 underflow for any attacker choosing a small
`block_len`, NDP32 for the signed-index path; the host selects the NTB
format). Impact class: **kernel memory disclosure** (and crash), not a
direct RCE; weaponizing the leak requires getting the OOB-copied skb
delivered back to the attacker — nontrivial, untested. Note this surface is
*USB*, not TCP/IP, but it is the concrete, verified memory-safety bug on
the device's kernel, reachable from the exact position we occupy.

The rest of the 5.10.0 kernel (TCP/IP stack itself) has no known
remotely-exploitable pre-auth flaw that is reachable given the minimal
listening surface (no TIPC/RDS/etc., no exposed netlink); the practical
kernel risk concentrates in the NCM gadget path.

### 4.3 dropbear 2019.78 (TCP 22) — no known pre-auth RCE

Desk research against upstream
[CHANGES](https://matt.ucc.asn.au/dropbear/CHANGES) and CVE databases,
for the *server* in the base's configuration (`-s`, publickey only, root
gated on vendor keys):

| Issue | Fixed in | Affects base? |
|---|---|---|
| CVE-2023-48795 (Terrapin, SSH prefix truncation) | 2023.86 | **No** — the only affected cipher (chacha20-poly1305) does not exist in 2019.78 (added 2020.79) |
| CVE-2020-36254 (dbclient arbitrary command via crafted server name) | 2020.79 | No — client-side |
| CVE-2021-36356 (deferred frees → OOM DoS) | 2021.x | DoS only, memory pressure (server) |
| CVE-2021-36369 (agent-forwarding prompt spoofing) | 2022.83 | No — client-side only (per upstream note) |
| 2026.92 authorized_keys long-line parsing bypass (`command=`) | 2026.92 | Requires attacker-controlled keys already in authorized_keys — N/A (vendor keys only) |
| 2026.90 OOB fd `close()` | 2026.90 | Unclear exploitability ("difficult to exploit", client/server) |
| 2025.89 unix-stream-forwarding priv-esc (CVE-2025-14282) | 2025.89 | No — affects 2024.84–2025.88 only |
| 2026.93 X11-forwarding UAF | 2026.93 | No — post-auth + X11 (not compiled/enabled) |

Rating: **low**. Password auth is disabled, no public CVE chain gives
pre-auth code execution on 2019.78. The realistic risk is unauthenticated
resource-exhaustion DoS (memory/conn floods), not RCE.

### 4.4 dnsmasq 2.81 — DNSpooq present, but DNS not reachable from usb0

dnsmasq 2.81 is inside the DNSpooq range (CVE-2020-25681…25687, fixed in
2.83):

- **25681/25682** — heap buffer overflows (`sort_rrset`) rated by Red Hat
  as *Important / remote code execution*; **require DNSSEC to be compiled
  and enabled** — unknown for this build (Buildroot default: off).
- **25683/25687** — DNSSEC-related overflow/DoS (25687 negative-size
  memcpy DoS).
- **25684/25685/25686** — cache-poisoning/birthday-attack weaknesses (no
  memory corruption).

However, **live probing shows no DNS listener on usb0:53** (TCP 53 closed;
UDP 53 silent to well-formed queries). The process runs as
`dnsmasq@usb0`; it is presumably serving DHCP only (`port=0`-style config)
on the PC side, so the DNS-side DNSpooq bugs appear unreachable from the
USB network. Whether DNS is served on the wireless interface
(10.0.0.0/28) is unverified — that would be the interesting remote
position. Rating from the USB host: **low** (conditional RCE if a DNS
listener exists elsewhere AND DNSSEC is enabled — both unconfirmed).

### 4.5 systemd-resolved (TCP/UDP 5355) — CVE-2022-2526, conditional

CVE-2022-2526 (fixed in systemd 249.11/250.5): use-after-free on
`DnsStream` in `resolved-dns-stream.c`; remotely triggerable by an
attacker who can act as / MITM the upstream DNS traffic of the resolver
(primarily a *server-side* attacker on the upstream path). The base's
systemd version is unknown (Buildroot ~2020 ⇒ likely 24x, i.e. vulnerable
era), but the trigger requires the resolver to talk upstream over TCP —
the base has no confirmed internet-facing resolver path (eth2_dhcp exists
but the deployment on our unit is USB-only). Rating from the analyzed
position: **low**. LLMNR itself is also a name-poisoning/MitM primitive
(nothing more on this device).

### 4.6 avahi (UDP 5353)

Answers enumeration queries. Known: CVE-2021-3468 (NULL deref DoS, fixed
0.8) — DoS only. No known RCE. Rating: **low** (DoS).

### 4.7 VirtualHere server (TCP 7575, only while paired)

Proprietary statically-linked binary, unauthenticated proprietary
protocol, no public CVE or security research found. mDNS advertises it
even while closed; on our unit it was closed in both live sessions
(unpaired). Because it only runs with the wireless link up, its exposure
to a *wireless-side* attacker (once on the AP) is the relevant question.
Rating: **unknown** — classic candidate surface (USB descriptors and
framing from network peers), zero public data.

## 5. Ranked RCE candidates

Updated after the active assessment (§6):

| # | Surface | Position | RCE potential | Confidence |
|---|---|---|---|---|
| 1 | imr_controller custom parser (34566/34567/34568) | USB host or wireless peer | High *if* a staging/reassembly bounds bug exists | **Reduced** — ~110 fuzz cases handled cleanly; staging is file-backed; validation robust (see §6) |
| 2 | `f_ncm` gadget `ncm_unwrap_ntb` (kernel 5.10.0) | USB host (us) | **CONFIRMED OOB read (CVE-2026-31617 pattern, live PoC)** — info-leak; RCE needs a second primitive | High — proven on hardware |
| 3 | dnsmasq 2.81 DNSpooq 25681/25682 | wireless peer, IF DNS is served there and DNSSEC enabled | RCE (heap overflow) | Low likelihood — both preconditions unconfirmed; also the base-head AP is 6 GHz AX, needs WiFi-6E hardware to even reach |
| 4 | systemd-resolved CVE-2022-2526 | upstream-DNS position | UAF → potentially code exec | Conditional, likely N/A on this deployment |
| 5 | dropbear 2019.78 | any network peer | none known pre-auth | — |
| 6 | avahi / LLMNR | any peer | DoS / name-poisoning only | — |

## 6. Active assessment findings (2026-10-07)

Authorized active testing on the owner's device. Tools: `scripts/fuzz_imr_controller.py`
(phases A–D), `scripts/head_impersonate.py`, `scripts/fake_head_pair.py`,
`scripts/report_chunk_oob.py`, `scripts/upload_complete_probe.py`,
`scripts/ncm_raw.py` + `scripts/ncm_unwrap_sim.py` (kernel PoC).

### 6.1 Control-protocol fuzzing — parser robust, no memory-corruption found

- **Phase A (pre-handshake framing, 36 cases):** src/dst device bytes > 3
  → connection closed (validated). Arbitrary 16-bit tags are echoed by the
  station without validating the `(device << 14) | txn` structure. The
  station answers `Connect` to *any* declared protocol version (even
  0xFFFFFFFF) — version negotiation is advisory. Packets addressed to
  `dst = PC` are routed back to the PC session (routing, not a reflector
  issue). Chunked reassembly (1 MB messages, double starts, end-only,
  sequence gaps/wraps) all handled silently or with `Nak`.
- **Phase B (post-handshake messages, 30 cases):** unknown types →
  broadcast `Nak` (tag 0); malformed bodies → `Nak`; identity byte 3
  (PC2) ignored on 34566; identity > 3 → close. No crashes.
- **Phase C (SoftwareUpdate staging, 24 cases):** per-chunk validation is
  solid — chunk index gaps, duplicates and overruns are `Nak 129`; the
  support-report name is strictly validated (`meta` only — no path
  traversal). **But**: `SoftwareUpdateData` payload length is **not**
  validated against `FinalPacketSize` at receive time (chunks larger than
  the declared final size are Ack'd), and there is **no global cap** on
  staging volume — see 6.2. Sending the complete declared chunk set makes
  the server finalize staging and drop the session; garbage files are
  rejected silently at validation (no error message, unlike the read
  channel which reports via `SoftwareUpdateComplete`).
- **Phase D (Protobuf wrapper, ~25 cases):** unknown content types →
  `Nak(133)`; malformed protobuf (nested groups, wiretype 7, truncated
  lengths) → `Nak(135) ExceptionCaught` — a C++ exception path, but
  handled. Content types 144 (Setup) and 147 (VirtualHere) answer with
  empty/valid Protobuf.
- **Phase E (Setup/Pairing field abuse, 23 cases):** `WirelessCountry`
  strings from empty to 60 000 bytes, `Ssid`/`Psk` byte fields to 60 KB,
  out-of-enum PairingType, EDID overflow — every case answered or ignored
  gracefully, no crash, and the persistent config afterwards was intact
  (`wi_country` unchanged). The country setter rejects values instead of
  copying them. The `Pairing` handler answers out-of-enum types with
  silence rather than a `Nak` (minor robustness gap, no security impact
  found).

### 6.2 Unauthenticated `/tmp` exhaustion (DoS) — proven, fixed by reboot

Two independent wedges were observed, both cleared by a reboot:

1. **Update staging**: during phase C, ~1 MB of update-staging chunks were
   accepted (16 × 65523 B against a declared 1-chunk transfer, all Ack'd,
   never completed). The staging file is **not released** when the session
   ends.
2. **Report generation accumulation**: every support-report `meta` request
   generates a fresh ~42-45 KB zip in `/tmp`; the flow only cleans up when
   the client completes the exchange (the `SoftwareUpdateComplete`-back
   step — the base answers it with `Disconnect`). A client that requests
   reports without completing (or requests chunk-data with a wrong-shaped
   request, which triggers a regeneration) wedges the generator within a
   handful of requests. This also explains the earlier "head unit /tmp"
   failure documented in PROTOCOL.md — it is not head-specific. Afterwards the
support report failed device-side with `SoftwareUpdateComplete`
"failed to open /tmp/support-report.zip" — the same error previously
observed only on the head unit. After `Setup.Reboot` the report generates again (content regenerated per
request, verified with a complete meta → chunk 0 → Complete exchange
returning a valid PK zip). Conclusion: **any unauthenticated peer on
192.168.3.0/24 can fill the base's `/tmp`** via either channel, degrading
the device until reboot. The upload channel is file-backed in `/tmp`, which
is also why no heap overflow occurs at chunk-append time.

### 6.3 Head impersonation — no authentication, but no additional surface while unpaired

A PC-side TCP peer can take the **head role** on 34567: the base answers
`Connect` with its own version and completes the handshake with no
authentication and no wireless link. However, as an unpaired fake head:
status queries are ignored, no `base→head` traffic is pushed, the
VirtualHere server (7575) does not start, and driving the pairing flow
(`Setup.Pair`) fails cleanly with `PairingState=Failure` — the pairing
state machine requires an RF-associated station. The `Pairing` replies
carry the SSID/PSK **encrypted** (binary blobs; consistent with
`ENCRYPT_PAIRING=1`), and the stored credentials were unchanged after the
failed pairing attempt. Value of this finding: the head role is not bound
to the wireless interface — relevant once WiFi-6E hardware is available.

### 6.4 Wireless side unreachable with current host hardware

The base-head link AP is **6 GHz 802.11ax**, not 2.4 GHz: `BaseStatus`
reports `WirelessChannel = 13` with `ChannelFreq = 6015` (6 GHz channel 13
= 6010 MHz, `Isax = 1`); the earlier "channel 13, 2.4 GHz" reading in
`wifi_probe_nofio.sh` was a misinterpretation of the same numbers. The
test host's Intel 8265 is 2.4/5 GHz only, so the AP is invisible to it
regardless of regdomain (verified with `iw reg set IT`). Reaching the
wireless-side surface (dnsmasq-on-wlp1s0 DNS? 7575 in paired state?
head-role services) requires a WiFi-6E adapter (e.g. Intel AX210/AX211).

### 6.5 Reverse-channel chunk-index validation (closed lead)

The read channel (support report) serves chunks on request
(`SoftwareUpdateMeta{FileType=5, PacketCount=i}` with an **empty** name —
the decompiled client never sends a name for chunk requests; sending the
`meta` name instead triggers a regeneration). Chunk indexes beyond the
actual chunk count are rejected with `Nak(129)` — the reader is
bounds-checked, no file-backed OOB read there.

### 6.6 Upload-staging name/size validation gaps (no path found to a write primitive)

On the upload channel (`FileType=2`) the staging **name is unvalidated**
— `linux.ub`, `zzz`, `a/b/c`, `../zzz`, `/etc/zzz`, `..`, 255-byte names
and empty names are all Ack'd (the read channel validates names
strictly). Combined with the file-backed staging this does not yield a
path-traversal write: the destination is the update pipeline, and the
validator rejects the content (`Disconnect` on garbage; no error message).
The two realistic abuse paths are the `/tmp` exhaustion (6.2) and the
declared-size mismatch (accepted, apparently unchecked until finalize) —
neither produced memory corruption in ~25 staging cases.

### 6.7 authorized_keys injection via staging — tried, disproven (2026-10-13)

The hypothesis: the upload staging file is created at a path derived from
the client-controlled `FileName`, so an incomplete transfer named
`../../root/.ssh/authorized_keys` with chunk 0 = an attacker public key
would plant a key in root's `authorized_keys` (dropbear 2019.78, publickey
only, reads it per attempt) → root shell on TCP 22. Fully tested live with
`scripts/authorized_keys_inject.py` and follow-up oracles. Result: **the
name is not used as a write path**, at any stage:

1. **Append oracle (EISDIR/ENOENT).** Staging with name `/root` (existing
   directory → `open(O_CREAT|O_WRONLY)` fails `EISDIR`) and
   `/root/nonexistentdir123/x` (`ENOENT`) — both Ack the *and* the
   full-size chunk 0 exactly like the `linux.ub` baseline. The chunk-append
   write target is therefore independent of the name (fixed or basename-
   sanitized path — either way unreachable for traversal).
2. **Chunk-size semantics discovered.** A chunk *shorter than 65523 bytes*
   is treated as the final chunk: the server finalizes staging, runs
   content validation, and rejects garbage with a silent `Disconnect`
   (tag 0). Full-size (65523 B) chunks are always Ack'd and the transfer
   stays open. This means the earlier "Disconnect on garbage" (6.6)
   fires at data time, not only at `Complete`.
3. **Finalize oracle (identical replies).** Completing a transfer
   (`count=1, final=100` + short chunk + `Complete(138)`) with names
   `linux.ub`, `/root`, `/root/nonexistentdir123/x` and
   `../../root/.ssh/authorized_keys` produces byte-identical reply flows
   (`Ack` → `Disconnect`, empty bodies, no error text) — no rename-to-name
   is observable, and the upload channel never surfaces error strings
   (unlike the read channel, which leaks `Failed to open
   /tmp/support-report.zip`).
4. **SSH oracle.** After each candidate staging (chunk 0 = the test
   ed25519 key padded to 65523 B with `#` comment lines, transfer left
   incomplete so the staged file persists per 6.2), root login attempts
   on TCP 22 always end in `Permission denied (publickey)`.

Related facts established the same day:

- A fresh support report confirms the staged incomplete transfer lives
  in `/tmp` (df jumps by the staged size; `/tmp` is a ~989 MB tmpfs, so
  the 6.2 "exhaustion" wedge is better explained as the generator's
  failed *open* than by space: after ~0.9 MB of unreleased staging the
  report flow fails with `Failed to open /tmp/support-report.zip` until
  `Setup.Reboot`, which resets it — reproducible and repeatable).
- The read channel's `meta` reply semantics: `PacketCount` = number of
  *full* 65523 B chunks, one extra *final* chunk of `FinalPacketSize`
  always follows (`count=0, final=43931` → single 43931-byte chunk 0).
- `Setup{LogLevel=4, UpdateSystemConf=true}` does not persist
  (`imr_controller_log_level` unchanged in a subsequently generated
  report; the earlier finding that config setters reject values holds),
  and the controller does not log staging activity to the journal at
  any level (a uniquely-named staging produced no journal trace).
- The support report dump includes `/settings/wi.conf` **in plaintext**:
  the 6 GHz AP SSID/PSK (`ssid=240104-02E3-NI-b`, `psk=<hex>`) — no need
  to obtain them via pairing. It also lists the config file set
  (`/settings/{factory,user,codec,system,wi}.conf`,
  `/etc/{hardware,build}.conf`), the exact dropbear invocation
  (`/usr/sbin/dropbear -F -R -s` — no custom authorized_keys path, so
  `/root/.ssh/authorized_keys` is confirmed as the target), and that
  **two** `imr_controller base` processes run concurrently.

Conclusion: the staging upload offers no path-controllable write; the
authorized_keys route is closed. The write primitives reachable from the
control protocol remain: the (validated) config setters and the update
pipeline's fixed staging path.

### 6.8 Update-package tar traversal — tried, disproven (2026-10-13)

Follow-up question: can anything be *executed* (or written) from `/tmp`?
No `/tmp` consumer executes files (boot scripts live in the initramfs;
`/tmp/boot_dmesg` is read by the report generator only), and the one
consumer with teeth — the update pipeline, which *does* unpack a staged
archive — was tested for extraction-before-signature-check:

- A structurally correct unsigned package (correct member names and
  `base/head_BOOT.BIN` entry sizes, hash-correct `SHA1SUMS`, garbage
  512-byte `SHA1SUMS.SIG`) carrying tar **path-traversal members**
  (`../../../root/.ssh/authorized_keys`, absolute) and **symlink
  members** (`d1 -> /root/.ssh` + `d1/authorized_keys`, a variant that
  survives leading-`..` stripping) was uploaded to completion.
  `scripts/update_traversal_probe.py` is the executable record.
- Result: no traversal/symlink write happened (SSH login stays
  `Permission denied (publickey)`; no marker in a subsequent report's
  `df`), and the finalize `Disconnect` arrives **0.06 s** after the last
  chunk even for a 119 MB (uncompressed) package — the device never
  gunzips, extracts or hashes unsigned content. The RSA-4096 gate over
  `SHA1SUMS` runs first; the "Unpacking update..." phase is reachable
  only for properly signed packages. No journal trace of validation.
- Consequence: the update channel ends at the same signature wall as
  secure boot; tar-extraction attacks (traversal, symlink, arbitrary
  write during unpack) are not reachable without the vendor signing key.

## 7. What remains for a future authorized assessment

- **VirtualHere server (7575, paired state) — now the primary shell-access
  candidate.** The staging/authorized_keys route is closed (6.7), the
  config setters reject values, and dropbear has no known pre-auth hole.
  What remains reachable today with the hardware on hand is the paired
  state: with the head powered on, the base exposes the proprietary,
  unauthenticated VirtualHere server streaming USB device records to any
  peer on 192.168.3.0/24 (see §1c). A C/C++ parser of network-framed
  binary records, never fuzzed — the largest untried attack surface.
- **imr_controller**: a long coverage-guided fuzzing campaign (thousands of
  cases, triage via the debug UART with `scripts/uart_capture.py`). The
  2026-10-07 campaign (~110 hand-crafted cases) found no memory corruption;
  the interesting remaining surfaces are the finalize/validation path after
  a complete-but-oversized staging set, and the `Pairing` handler (which
  answered a garbage payload with silence rather than a `Nak`).
- **f_ncm weaponization**: turn the proven OOB read into a disclosure of
  *foreign* kernel data. The NDP32 parser-switch and the 32-bit-index OOB
  read are now proven live; what remains is slab grooming past the rx
  buffer into adjacent objects (kernel pointers / KASLR defeat) and the
  below-buffer signed-index read (sim-validated only). A crash-based
  variant (aiming the index at unmapped memory) was deliberately not
  attempted.
- **Wireless side**: obtain a WiFi-6E adapter and join the base's 6 GHz AX
  AP (SSID/PSK known), then port-scan 10.0.0.1 to establish which
  listeners (dnsmasq DNS? VirtualHere 7575? head-facing 34567?) are exposed
  there — this is the position where DNSpooq (if DNSSEC is enabled) and
  the unauthenticated head role would become remotely relevant.

## 8. References

- DNSpooq: JSOF disclosure, CVE-2020-25681–25687 (fixed dnsmasq 2.83)
- CVE-2022-2526: systemd-resolved DnsStream UAF (Qualys, fixed 249.11/250.5)
- dropbear upstream CHANGES/security history: https://matt.ucc.asn.au/dropbear/
- Linux f_ncm gadget fixes: kernel CVE records CVE-2026-31617
  (minimum block_len validation) and CVE-2026-74679 (unsigned ndp_index);
  pre-fix code verified at tag v5.10 of
  `drivers/usb/gadget/function/f_ncm.c`
- Base software inventory: live support report (see
  [firmware/firmware_flashing.md](../firmware/firmware_flashing.md) §7.2/§9)
- Control protocol format: [docs/PROTOCOL.md](PROTOCOL.md)
