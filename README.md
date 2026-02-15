## Network Sniffer

A Python-based packet sniffer that captures and analyzes network traffic in real-time. This educational tool demonstrates low-level network protocol structures by parsing Ethernet frames, IPv4 packets, and transport layer protocols.

## Features

- 📡 Captures live network packets using raw sockets
- 🔍 Parses Ethernet frames (source/destination MAC addresses)
- 🌐 Analyzes IPv4 packets (IP addresses, TTL, protocol type)
- 📊 Decodes transport layer protocols:
  - **TCP**: Ports, sequence numbers, flags (SYN, ACK, FIN, etc.)
  - **UDP**: Ports, packet length
  - **ICMP**: Type, code, checksum
- 📝 Formatted output with proper indentation for easy reading

## Requirements

- Python 3.x
- Linux/Unix-based OS (uses `AF_PACKET` sockets)
- Root/administrator privileges

## Usage 
sudo python3 network_sniffer.py

## Sampe Output
Ethernet Frame:
  - Destination: 00:50:56:E4:A9:2D, Source: 00:0C:29:19:11:A4
  - IPv4 Packet: 192.168.1.100 -> 142.250.185.46
  - TCP Segment: Port 54321 -> 443, Flags: ACK

## Functions
ethernet_frame(): Parses Ethernet header
ipv4_packet(): Extracts IP header info
tcp_segment(): Decodes TCP segment
udp_segment(): Decodes UDP datagram
icmp_packet(): Parses ICMP packets

## Limitations
Pv4 only (no IPv6)
Linux-specific (AF_PACKET)
Requires root privileges

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/basic-network-sniffer.git
cd network-sniffer
