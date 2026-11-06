# System Architecture

This document describes the architecture of the nofio-linux open source implementation.

## Overview

The Nofio wireless VR system consists of the following components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        PC (Linux/Windows)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   SteamVR       │    │   OpenVR Driver  │    │  Utility    │  │
│  │                 │    │  (driver_nofio)  │    │  (optional)  │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│           ▲                  ▲  ▲  ▲                ▲           │
│           │                  │  │  └────────────────┘           │
│           │                  │  │                                   │
│           │                  │  └─── USB Interface (Virtual)  │
│           │                  │                                      │
└────────────────────────────────┼──────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Nofio Base Station                            │
├─────────────────────────────────────────────────────────────────┤
│  VID:PID: 04b3:4010                                                  │
│  Chipset: QCA2066 WiFi                                               │
│  Firmware: base_BOOT.BIN                                            │
│  Network: 192.168.3.1:7575 (VirtualHere Server)                      │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼ (WiFi QCA2066)
┌─────────────────────────────────────────────────────────────────┐
│                    Nofio Head Adapter                             │
├─────────────────────────────────────────────────────────────────┤
│  Chipset: QCA2066 WiFi                                             │
│  OS: QNX6 Neutrino                                               │
│  Firmware: head_BOOT.BIN                                          │
│  Connection: Oculink USB to Valve Index                           │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Valve Index Headset                            │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. SteamVR driver — none (removed)

The original product ships `driver_nofio.dll`, but its analysis showed it is
only a **settings/status companion** (`nofio_settings`; no USB/network/display
I/O) — the streaming path runs through SteamVR's **native Valve Index driver**
over VirtualHere.

### 2. Utility Application

The utility provides GUI and management functionality, replacing the original `nofioUtility.exe` (.NET 7) with a cross-platform Dart + Flutter application.

#### Architecture

```
┌─────────────────────────────────────────────┐
│                 MainApp (Flutter)                │
│  + main()                                       │
│  + build()                                      │
│  + initState()                                  │
└────────────────────┬────────────────────────┘
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
┌─────────────────────┐ ┌─────────────────────┐
│   SettingsService    │ │   FirmwareService   │
│  + loadSettings()    │ │  + checkUpdates()  │
│  + saveSettings()    │ │  + download()     │
│  + getSetting()      │ │  + install()       │
└─────────────────────┘ └─────────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────────┐
│              DeviceService (FFI)                 │
│  + getStatus()      → libusb / network          │
│  + pairDevices()    → base ↔ head              │
│  + readDiagnostics()                            │
└─────────────────────────────────────────────┘
```

## Communication Flow

### Current (VirtualHere-based)

```
PC Application → VirtualHere Client → Network (192.168.3.1:7575) → VirtualHere Server → USB Device
```
