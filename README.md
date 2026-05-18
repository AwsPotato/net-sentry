# Net-Sentry
A high-performance, modular network packet sniffer for Windows, written in modern C++20.

## Overview
Net-Sentry utilizes the Npcap SDK to capture packets and process them through a non-blocking modular routing system. It's designed to instantly map raw packets into metadata structs, which are passed efficiently into specialized C++ components.

### Pluggable Modules
1. **DNS Tracker** (`src/dns_tracker.hpp`): Inspects UDP port 53 packets, cleanly parsing byte payload structures to extract and log queried domain strings.
2. **Game Telemetry** (`src/game_telemetry.hpp`): Tracks active UDP streams and calculates arrival variance (jitter) in microseconds to monitor dynamic connection stability.
3. **Intrusion Detector** (`src/intrusion_detector.hpp`): Monitors incoming TCP/UDP connections grouped by source IP. Tracks distinct destination ports to spot aggressive multi-port scanning behavior in real-time.

## Project Structure
```text
Net-Sentry/
├── CMakeLists.txt           # Build configuration
├── README.md                # Documentation
└── src/
    ├── main.cpp             # Npcap initialization, active NIC selection, and primary loop
    ├── packet_utils.hpp     # Standardized byte-aligned structs for precise header unmapping
    ├── dns_tracker.hpp      # DNS processing module
    ├── game_telemetry.hpp   # Stream tracking module
    └── intrusion_detector.hpp # Security analysis module
```

## Dependencies & Installation

This project requires the **Npcap SDK** for Windows packet capture.

### Prerequisites:
1. **[Npcap Driver](https://npcap.com/#download)**: Install with the "Install Npcap in WinPcap API-compatible Mode" option checked.
2. **[Npcap SDK](https://npcap.com/guide/npcap-devguide.html)**: Download the SDK zip and extract it to a known directory (e.g., `C:\Npcap-SDK`).
3. **CMake 3.20+**: To generate build files.
4. **MSVC Compiler** (Visual Studio 2022 recommended): For robust C++20 support.

### Build Instructions

1. Open a command prompt or developer terminal in the project root directory.
2. Run the CMake generation command. Be sure to point `-DNPCAP_DIR` to where you extracted the SDK.
   ```bash
   cmake -S . -B build -DNPCAP_DIR="C:/Npcap-SDK"
   ```
3. Compile the executable:
   ```bash
   cmake --build build --config Release
   ```
4. Run the resulting executable **as Administrator**. Npcap strictly requires elevated privileges to intercept raw interface traffic.
   ```bash
   .\build\Release\NetSentry.exe
   ```

---

## Interactive GUI Features

Net-Sentry features a beautiful dark-mode interface built on ImGui, offering real-time network visualization:
* **Interactive Adapters**: Live selection of active physical or virtual network interfaces.
* **Copyable DNS Feed**: Every DNS request captured in the feed is fully interactive. Simply **click any row** in the feed to copy the QNAME directly to your system clipboard instantly!
