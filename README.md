# Network Packet Analyzer

## Overview

This repository contains a basic packet sniffer tool implemented in Python using the `scapy` library. The tool captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data. This tool is designed for educational purposes to help users understand network traffic and protocols.

## Features

- Captures network packets in real-time
- Displays source and destination IP addresses
- Identifies the protocol (TCP, UDP, or other)
- Shows the first 30 bytes of the packet payload

## Requirements

- Python 3.x
- `scapy` library
- `Npcap` (for Windows users)

## Installation

1. **Install Python Dependencies**:
    ```bash
    pip install scapy
    ```

2. **Install Npcap (Windows Only)**:
    - Download and install Npcap from [Npcap's official site](https://nmap.org/npcap/).
    - Ensure to select "Install Npcap in WinPcap API-compatible Mode" during installation.

## Usage

1. **Determine Network Interface**:
    - List available network interfaces using the following script:
        ```python
        from scapy.all import get_if_list
        print(get_if_list())
        ```

2. **Run the Packet Sniffer**:
    - Replace `'Wi-Fi'` in the script with the correct interface name obtained in the previous step.
    - Run the script with administrator/root privileges:
        ```bash
        sudo python3 packet_sniffer.py  # On Linux/Mac
        python packet_sniffer.py        # On Windows (run Command Prompt as Administrator)
        ```
