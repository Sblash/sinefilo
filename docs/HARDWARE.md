## Hardware Information

(verified live from the boot log and USB descriptors, 2026-10 — see [docs/HARDWARE_ACCESS.md](docs/HARDWARE_ACCESS.md))

- **SoC:** Xilinx Zynq UltraScale+ MPSoC **ZU3CG** on a **Trenz TE0803** SoM (custom IMRNext carrier), FPGA fabric "spark-60", secure boot enforced (AES eFUSE/BBRAM device key + RSA-2048)
- **Boot:** QSPI Micron n25q00a 256 MiB (dual-parallel), BOOT.BIN (ZynqMP bootgen) + encrypted FIT blob; U-Boot 2021.01 → Linux Buildroot 2020.05.1
- **Base VID:PID:** 04b3:1234 ("Nofio Wireless Base", IMRNext; verified live, CDC-NCM network class, single configuration)
- **OS:** Buildroot Linux 5.10.0-nofio (aarch64, **initramfs in RAM**, `root=/dev/ram0`)
- **WiFi:** QCA2066 (Qualcomm, WiFi 6E) + 60 GHz Wilocity-family radios (`wil6210.fw`, `wil6436.fw`); base is the AP, base↔head link is 6 GHz 802.11ax
- **Network:** USB CDC-NCM, 192.168.3.0/24 (base 192.168.3.1); the base also runs a WiFi AP for the head
- **Control ports (base):** TCP 22 (dropbear, publickey-only), 34566/34567 (`imr_controller`), 7575 (VirtualHere, only while paired)
- **Debug:** UART pads under the SoM (SoC console 115200), MCU/SP console 38400, JTAG pads at 1.8 V — see [docs/HARDWARE_ACCESS.md](docs/HARDWARE_ACCESS.md)