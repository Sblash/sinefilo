# Boot Chain & Secure Boot — Crypto Verdict

**Verdict up front: the firmware can be neither decrypted nor re-encrypted
offline.** The AES key is the per-device key in eFUSE/BBRAM and is not embedded
anywhere in the bootloader; extracting it would require JTAG on the PMU TAP
(excluded by decision). The `firmware/` directory is therefore **archived** —
kept for reference, no further work planned.

## 1. BOOT.BIN layout (QSPI mtd0, verified from flash + OCM dump)

Standard Xilinx ZynqMP bootgen image (no vendor header). Partition table in
flash at 0x8C0 (and mirrored hot in the FSBL `PartitionHeader[8]`):

| # | Partition | flash offset | size | load address | notes |
|---|-----------|--------------|------|--------------|-------|
| 0 | fsbl.elf | 0x2800 | 103 KB | 0xFFFC0000 (OCM) | encrypted in flash |
| 1 | pmufw.elf | 0x1C980 | 91 KB | PMU TCM 0xFFDC0000 | encrypted |
| 4 | fpga.bit | 0x36A80 | 5.31 MB | PCAP (0xFFFFFFFF) | the FPGA bitstream |
| 5 | bl31.elf | 0x587280 | 50 KB | 0xFFFEA000 | TF-A v2.4 xilinx-v2021.2 |
| 6 | u-boot.elf | 0x594980 | 1.19 MB | 0x08000000 | U-Boot 2021.01 |
| 7 | linux.ub (FIT blob) | **0x10A0000** | 42,075,788 B | 0x10000000 | the OS image |

Flash chip: Micron n25q00a 256 MiB, **dual-parallel 2×64 MB**. mtd0 "boot_all"
is 96.7 MB; free slack 0x6D0000–0x10A0000 (~9.7 MB) and after ~0x38C0000.

## 2. Crypto schema (from the FSBL in the OCM dump, r2/capstone vs Xilinx
embeddedsw v2021.2 sources)

- AES-256-**GCM in the CSU hardware** (0xFFCA1000 + CSU DMA 0xFFC80000), no
  software AES.
- Key selection `KeySel=1 (DEV)`: the key is the **device key (eFUSE or BBRAM —
  the code cannot distinguish)**. **No key is embedded in the FSBL**, and no key
  material survives in the OCM dump. Offline decryption without the device key is
  impossible.
- Each partition blob starts with a 48-byte **secure header** (partition AES key
  32 B ‖ IV 12 B ‖ next-block length 4 B) encrypted with the device key, followed
  by repeated `[ciphertext][16 B GCM tag]` blocks. Key rolling bootgen with the
  KUP register zeroed after use. Base IV `75 F6 D0 B1 B9 5A B1 C5 C7 DE 71 05`,
  last byte = partition index.
- Signature: **RSA-2048** (correction: not 4096) + **SHA3-384** on **all**
  partitions, PPK selected from eFUSE. The inner FIT is *not* signed (it is
  covered only by the encrypted blob's GCM tag).
- The "Bus error" reading CSU/eFUSE from Linux is secure-only hardware gating,
  not an XPPU policy.

## 3. Inner FIT (seen decrypted in RAM via `iminfo 0x10000000`)

- kernel gzip ~40 MiB with **built-in initramfs** (no separate ramdisk image;
  `root=/dev/ram0`), plus two dtbs; configs `nofio1_dp_head` (default) and
  `nofio1_mipi_base` — same image ships for base and head.
- Integrity: **sha1 hash only, no RSA signature** on the FIT — but re-flashing a
  modified FIT is still impossible because the outer blob must be re-encrypted
  with the device key.

## 4. U-Boot 2021.01 facts (from the RAM dump, `uboot_ram.bin`)

- `bootdelay=-2` compiled in → no manual interrupt window (continuous flood
  needed, see [HARDWARE_ACCESS.md](HARDWARE_ACCESS.md)).
- `bootcmd_qspi0 = sf probe 0 0 0 && echo QSPI: Not using boot script for now && bootm 0x10000000#${hw_series}_${hw_type} && ...`
  — the boot-script hook on the QSPI path is **stubbed by the vendor**
  ("Not using boot script for now", literal). boot.scr exists only for
  jtag/nand/usb-dfu/usb-thor boot modes never used on retail.
- `CONFIG_ENV_OFFSET = 0x1400000`, `ENV_SIZE = 0x10000`, **non-redundant** —
  the offset falls **inside the encrypted FIT** (0x10A0000–0x38C0000), so
  **`saveenv` = brick**. The vendor never saves the env ("bad CRC, using default
  environment" at every normal boot).
- `sf probe` works in normal boots; the garbage JEDEC IDs appear only in
  flood-interrupted sessions (controller left mid-transaction).

## 5. Consequences

1. **Custom firmware on stock hardware: impossible** without the vendor's
   private RSA key or the device key — `firmware/` is archived
   ([boot_image_format.md](../firmware/boot_image_format.md),
   [firmware_analysis.md](../firmware/firmware_analysis.md),
   [firmware_flashing.md](../firmware/firmware_flashing.md)).
2. What *is* possible without touching the signed chain: runtime patching via the
   persistent-root config injection ([ROOT_PERSISTENCE.md](ROOT_PERSISTENCE.md)),
   diagnostics on the live system, and a formal GPL source request (kernel +
   U-Boot + Buildroot; the FPGA bitstream / SP firmware are out of GPL scope).
3. Endgame brainstormed and kept in the raw logs: `kexec` into an unsigned kernel
   (needs CONFIG_KEXEC/lockdown check), overlayfs patch-layer driven by the
   persistent payload, GPL-requested exact kernel + TE0803 DTS.
