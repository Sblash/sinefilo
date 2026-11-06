# nofio-linux

Open source implementation for Nofio wireless VR adapter (Valve Index).

> **Disclaimer:** this is an independent, community reverse-engineering project
> for interoperability purposes. It is not affiliated with, endorsed by, or
> sponsored by IMRNext. No vendor binaries,
> firmware images, or third-party proprietary software are distributed in this
> repository.

## Credits
[PanicHandler](https://github.com/PanicHandler) - for helping me to decompile and analyze the original utility app

[giampaolo23](https://github.com/giampaolo23) - to collaborate with me on the discovery of Nofio and the development of the open-source utility app 

[MenachemSchmuel](https://github.com/MenachemSchmuel) - for betatesting of the old guide and correction of my (bad) english

## Project Status

**Current Phase:** 3 - Open-source utility app

## Overview

Nofio is a wireless adapter for the Valve Index VR headset that uses VirtualHere for USB-over-IP communication between the base station and the PC. This project seeks to:

- Provide native Linux support
- Recreate the utility app as open source
- Enable community development and bug fixes (runtime patch layer via [docs/ROOT_PERSISTENCE.md](docs/ROOT_PERSISTENCE.md))
- Prevent hardware abandonment (e-waste)

## Quick Start

For the current VirtualHere-based solution, see [docs/ORIGINAL_README.md](docs/ORIGINAL_README.md).

**Note:** the VirtualHere client is **not** distributed in this repository
(it is third-party proprietary software). You need the Linux Intel x64 client
(`vhuit64`), available from [virtualhere.com](https://www.virtualhere.com/download).
Version **5.7.7** is the one bundled by the original Nofio utility and the one
tested here. The `vhui.ini` configuration it needs is documented (with
device-specific credentials redacted) in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Documentation

- [Analysis Report](docs/ANALYSIS.md) - Reverse engineering report (static analysis of the shipped software)
- [Architecture](docs/ARCHITECTURE.md) - System architecture
- [Protocol](docs/PROTOCOL.md) - Communication protocol (verified live)
- [Security Analysis](docs/SECURITY_ANALYSIS.md) - TCP/IP attack surface of the base (live assessment)
- [Hardware Access](docs/HARDWARE_ACCESS.md) - UART/JTAG pads, consoles, U-Boot interrupt, root shell, safety rules
- [Root Persistence](docs/ROOT_PERSISTENCE.md) - persistent root via config injection (verified)
- [Boot Chain & Crypto](docs/BOOT_CHAIN.md) - secure boot chain, crypto verdict, flash map, U-Boot facts
- [Utility Codebase Analysis](docs/UTILITY_CODEBASE_ANALYSIS.md) - Analysis of the original nofioUtility.exe (decompiled)
- [Original Guide](docs/ORIGINAL_README.md) - Original Linux setup guide
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- `firmware/` — 🗄️ **archived** (reference only): BOOT.BIN is a secure-boot ZynqMP image (AES device key in eFUSE/BBRAM + RSA-2048); decrypt/re-encrypt offline is impossible, see [docs/BOOT_CHAIN.md](docs/BOOT_CHAIN.md)
- `miscellaneous/` — raw material: decompiled utility, extracted rootfs, PCB photos, raw session logs (`mistral-nofio-knowledge/`), analysis notes

## Phases

### Phase 1: Static analysis of the shipped software
- [x] `nofioUtility.exe` decompiled and analyzed — [docs/UTILITY_CODEBASE_ANALYSIS.md](docs/UTILITY_CODEBASE_ANALYSIS.md), [docs/UTILITY_CONCEPTUAL_MAP.md](docs/UTILITY_CONCEPTUAL_MAP.md)
- [x] Firmware package structure: BOOT.BIN image format + utility flashing flow (static) — `firmware/boot_image_format.md`, `firmware/firmware_flashing.md`

> **Custom SteamVR driver development is excluded — we won't write one.**
> The streaming path already works through SteamVR's **native Valve Index
> driver** over VirtualHere; the original `driver_nofio.dll` is only a
> settings/status companion (no USB/network/display I/O), so there is nothing
> to reimplement. The `driver/` folder has been removed from this repo, and
> the old "direct USB protocol bypassing VirtualHere" goal is dropped with it.

### Phase 2: Dynamic analysis & device access
- [x] Live recon of the base over USB + attack-surface assessment — [docs/SECURITY_ANALYSIS.md](docs/SECURITY_ANALYSIS.md)
- [x] Control protocol reverse engineered and verified live (TCP 34566/34567, protobuf) — [docs/PROTOCOL.md](docs/PROTOCOL.md)
- [x] Hardware detection (VID:PID 04b3:1234 base, verified live; head TBD)
- [x] VirtualHere integration as interim solution (client 5.7.7) — hub *research* retired
- [x] UART/U-Boot access to the base + root shell in RAM — [docs/HARDWARE_ACCESS.md](docs/HARDWARE_ACCESS.md)
- [x] Persistent root via config injection, verified — [docs/ROOT_PERSISTENCE.md](docs/ROOT_PERSISTENCE.md)
- [x] Firmware / boot-chain analysis (🗄️ track archived, reference only):
  - [x] Secure-boot crypto characterized from the FSBL/OCM dump: AES-256-GCM device key (eFUSE/BBRAM) + RSA-2048/SHA3-384 — **firmware can be neither decrypted nor re-encrypted offline** — [docs/BOOT_CHAIN.md](docs/BOOT_CHAIN.md)
  - [x] Flash map + U-Boot facts (ENV_OFFSET inside the encrypted FIT → never `saveenv`; boot script stubbed) — [docs/BOOT_CHAIN.md](docs/BOOT_CHAIN.md), [docs/HARDWARE_ACCESS.md](docs/HARDWARE_ACCESS.md)
  - [x] Device-side rootfs analyzed (Buildroot 2020.05.1, `imr_controller`, boot hooks) — `miscellaneous/ROOTFS_2.5.0_ANALYSIS.md`
  - [~] Custom/open firmware on stock hardware — **impossible** (secure boot only launches vendor-signed images) → closed
  - [ ] ~~QCA2066 / 60 GHz wireless-side research~~ — dropped (scripts removed)
  - [ ] GPL source request to support.nofio.co (kernel/U-Boot/Buildroot, exact version) — optional, recommended

### Phase 3: Open-source utility app (Dart + Flutter)
- [ ] Open-source app reimplementation for Linux
- [ ] Reading nofio-base status (TCP 34566 — [docs/PROTOCOL.md](docs/PROTOCOL.md))
- [ ] Patch injection
- [ ] Advanced settings
- [ ] Pairing (nofio-base <-> nofio-head)
- [ ] Logging and diagnostics

### Phase 4: Optimizations and fixes
- [ ] Fix current nofio firmware bugs via the runtime patch layer (persistent root, [docs/ROOT_PERSISTENCE.md](docs/ROOT_PERSISTENCE.md)) — e.g. the known "red screen" / audio-drop issues
- [ ] Latency optimization

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See [LICENSE](LICENSE) for details.

## Resources

- [ValveSoftware/openvr](https://github.com/ValveSoftware/openvr) - OpenVR SDK
- [Sblash/nofio-linux](https://github.com/Sblash/nofio-linux) - Original Linux guide
- [Buildroot](https://buildroot.org/) - The device OS build system
- [Xilinx/zynqmpimage (u-boot)](https://github.com/Xilinx/u-boot-xlnx/blob/master/tools/zynqmpimage.h) - ZynqMP boot image format reference
- [uboot-interupt (sharmaniraj009)](https://github.com/sharmaniraj009/uboot-interupt) - U-Boot autoboot interrupt flood used for serial access

## Contact

For questions or discussions, please open an issue on GitHub.
