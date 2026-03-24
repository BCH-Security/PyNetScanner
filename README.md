# Network Scanner (ARP, ICMP, TCP Port Scanning)

A multi-threaded network scanning tool built in Python using Scapy.  
This tool performs host discovery and port scanning using multiple techniques commonly used in penetration testing.

---

## Features

- ARP scan for local network discovery  
- ICMP (ping) scan with multi-threading  
- TCP port scanning with multiple techniques:
  - SYN scan
  - FIN scan
  - ACK scan
  - XMAS scan  
- Multi-threaded port scanning for performance  
- Port range support (e.g. `1-1000`)  
- Scan all ports (`1–65535`)  
- Clean output with filtering of closed ports  
- CLI-based interface  

---

## Requirements

- Python 3.x  
- Scapy  

Install dependencies:

```bash
pip install scapy
```


## General Syntax
```bash
python3 network-scanner.py -m <mode> [options]
```

## Scan Modes

- ARP scan

Discover active hosts in a local network.
```bash
python3 network-scanner.py -m arp -t 192.168.1.0/24
```

- ICMP Scan (Ping Sweep)

Scan a subnet to find live hosts using ICMP requests.
```bash
python3 network-scanner.py -m icmp -t 192.168.1.0/24 --threads 20
```

- Port Scanning

Basic SYN scan:
```bash
python3 network-scanner.py -m port -p 22,25,53,80,443,8080 -t 192.168.1.10 --scan-type syn --threads 5
```

Port range scan:
```bash
python3 network-scanner.py -m port -p 1-1000 -t 192.168.1.10 --scan-type syn --threads 100
```

Scan all ports:
```bash
python3 network-scanner.py -m port --all-ports -t 192.168.1.10 --scan-type syn --threads 100
```

## Scan Types
- syn  → SYN scan (stealthy, half-open scan)
- fin  → FIN scan
- ack  → ACK scan
- xmas → XMAS scan

Example Using XMAS scan:
```bash
python3 network-scanner.py -m port -p 22,25,53,80,443,8080 -t 192.168.1.10 --scan-type xmas --threads 5
```
