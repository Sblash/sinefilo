# Hardware Debug Access (UART / JTAG) — Nofio Base

## 1. Board identity (verified from the live boot log)

| Item | Value |
|---|---|
| SoC | Xilinx Zynq UltraScale+ MPSoC **ZU3CG** (Chip ID `zu3cg`), DRAM 2 GiB |
| SoM | **Trenz TE0803** (`nofio1-te0803-03-3ae11-a`) — commercial module, public datasheet |
| FPGA fabric | `spark-60 (f5ac868)`, 2024-05-10 |
| Hardware IDs | `hw_series=nofio1`, `hw_type=mipi_base` (base) / `nofio1_dp_head` (head) |
| Boot flash | QSPI Micron **n25q00a 256 MiB** (dual-parallel 2×64 MB per the FSBL driver) |
| Boot chain | FSBL → pmufw → bl31 (TF-A v2.4) → **U-Boot 2021.01** → Linux Buildroot 2020.05.1 (kernel 5.10.0-nofio, **initramfs in RAM**, `root=/dev/ram0`) |
| Power | 12 V DC barrel (Valve Index PSU-compatible); USB-C is **data only** |

## 2. Test pads on the back of the PCB

- `SOC_TCK/TMS/TDI/TDO` — JTAG of the ZynqMP, **1.8 V LVCMOS18** (measured 1.80 V).
  The Pi's 3.3 V GPIO must NOT drive these: use an FT2232H with Vref 1.8 V or a
  level shifter. JTAG is currently **excluded by decision** (software-only path).
- `MCU_TCK/TMS/TDI/TDO`, `MCU_TX/RX` — belong to the wireless-module MCU
  ("SP", Service Processor, fw "MCU Version 2.14").
- `DEBUG_CD#` — strap, active-low, ~10 kΩ pull-down to GND (measured 1.22 V when
  powered). Tested: no effect on the consoles. Function unknown.
- `PS_MODE0/1` — ZynqMP boot-mode straps (never touch without a series resistor).
- **Group of 7 pads under the SoM**: two adjacent pads are the **SoC console
  UART (TX/RX, idle-high ~1.8 V at wake)**; `ERR_OUT`/`ERR_STATUS` are status
  flags; reference GND = the USB-C shell (verified continuity).

Contact technique without soldering (pads are flat, center-board): tinned wire
tips pressed on the pads and held with **Kapton tape** (never ordinary insulating
tape — it leaves adhesive residue that caused a real short once), safety loop
mid-cable, needle-in-Dupont probe for quick tests, **1 kΩ in series on every
signal line**, GND always first, never 5 V anywhere. Verify contacts with a
loopback (touch the two probe tips together: typed chars must echo back).

## 3. The two consoles

1. **SP/MCU console — 38400 baud, log-only.** On `MCU_TX`. Speaks only at events
   (wake / power-rail bring-up / "SOM released from reset" / sleep / power-down).
   The SP manages power rails + clocks and releases the SoC from reset; the
   SOM↔SP control channel is bidirectional ("CPU requested power down" /
   "CPU didn't respond, powering down anyway"). Interactive RX is deaf in retail
   firmware — do not expect a prompt.
2. **SoC console — 115200 baud.** On the pad pair under the SoM. Full boot log:
   FSBL → U-Boot → kernel → systemd. This is the useful one.

## 4. Getting a root shell (U-Boot interrupt → initramfs shell)

U-Boot is compiled with `bootdelay=-2`: **no manual interrupt window**, a
continuous character flood is required.

```bash
# on a Raspberry Pi 3B (serial console disabled in raspi-config, pyserial installed)
python3 interupt.py --mode continuous --port /dev/serial0   # https://github.com/sharmaniraj009/uboot-interupt
# power-cycle the base while it floods; when "ZynqMP>" appears in the output: Ctrl+C
screen /dev/serial0 115200        # Enter → live U-Boot prompt (no timeout now)
```

At the prompt:

```
setenv bootargs "${bootargs} rdinit=/bin/sh init=/bin/sh"
bootm 0x10000000#nofio1_mipi_base
```

Use the config name **explicitly**: the flood interrupts the retail step that sets
`hw_series`/`hw_type`, so `bootm ...#${hw_series}_${hw_type}` fails with "Could not
find configuration node". Result: **root shell in RAM** (initramfs; nothing
persists by design).

### Full system without losing the shell

```sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
sed -i 's/^root:[^:]*:/root::/' /etc/shadow
# the vendor MASKS the serial getty with a symlink to /dev/null — remove it:
rm /etc/systemd/system/serial-getty@ttyPS0.service
systemctl enable serial-getty@ttyPS0
exec /sbin/init
# after boot: just press Enter → "login: root" (empty password); dmesg -n 1 to silence logs
```

## 5. Flash map and permanent safety rules

`/proc/mtd`: `mtd0 "boot_all"` 96.7 MB (erasesize 0x2000), `mtd1 "settings"`
128 KB (jffs2, **persistent**), `mtd2 "data"` 20 MB.

mtd0 layout (64K blocks): **BOOT.BIN 0x0–0x6C0000** · free 0x6D0000–0x10A0000
(~9.7 MB) · **encrypted FIT blob 0x10A0000–0x38ADE9C**. See
[BOOT_CHAIN.md](BOOT_CHAIN.md).

- 🔫 **NEVER run `saveenv` / `fw_setenv` / `dd` at 0x1400000 on mtd0.**
  U-Boot's `CONFIG_ENV_OFFSET = 0x1400000` falls **inside the encrypted FIT**:
  writing the env there corrupts the kernel image = instant brick.
- ⚠️ In a RAM shell, **always mount /proc /sys /dev before any `dd` on mtd** —
  without them `dd` fails *silently* and every block looks "free" (false positive).
- `/dev/mem` is STRICT_DEVMEM: RAM reads are EPERM; the OCM (0xFFFC0000) is
  readable only via `devmem`; CSU/eFUSE reads give Bus error (secure-only gating).
- `sf probe` works during **normal** boots (the FSBL preloads everything); the
  garbage JEDEC IDs appear only in flood-interrupted sessions. The vendor never
  saves the env ("bad CRC, using default environment" at every boot).
- BusyBox grep has no `-abo`: to search flash use `dd ... | tr '\000' '\n' | grep -q 'str'`.
- Serial paste truncates long lines — type short commands by hand.
