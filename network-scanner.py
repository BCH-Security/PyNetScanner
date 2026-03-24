#!/usr/bin/env python3

import logging
import scapy.all as scapy
import argparse, sys, ipaddress, threading, queue, random

# Colors
R="\033[1;31m"; Y="\033[1;33m"; C="\033[1;36m"; W="\033[0m"

scapy.conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# =========================
# ARP SCAN
# =========================
def arp_scan(target):
    print(R, "Starting ARP Scan...", W)

    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target)
    ans = scapy.srp(pkt, timeout=1, retry=1, verbose=False)[0]

    for _, rcv in ans:
        print(C, f"{rcv.psrc:16}  {rcv.hwsrc}", W)

    print()


# =========================
# ICMP SCAN (THREADED)
# =========================
def icmp_worker(q):
    while not q.empty():
        ip = str(q.get())
        pkt = scapy.IP(dst=ip)/scapy.ICMP()

        ans = scapy.sr(pkt, timeout=1, retry=1, verbose=False)[0]

        for _, rcv in ans:
            print(C, "Live Host:", rcv.src, W)

        q.task_done()


def icmp_scan(subnet, threads):
    print(R, "Starting ICMP Scan...", W)

    q = queue.Queue()
    for ip in ipaddress.IPv4Network(subnet):
        q.put(ip)

    for _ in range(threads):
        t = threading.Thread(target=icmp_worker, args=(q,))
        t.daemon = True
        t.start()

    q.join()
    print()


# =========================
# PORT SCAN FUNCTIONS
# =========================

def syn_scan(ip, port, timeout):
    sport = random.randint(1025, 50000)
    pkt = scapy.IP(dst=ip)/scapy.TCP(sport=sport, dport=port, flags='S')
    resp = scapy.sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return "filtered"
    elif resp.haslayer(scapy.TCP):
        if resp[scapy.TCP].flags == 0x12:
            scapy.send(scapy.IP(dst=ip)/scapy.TCP(sport=sport, dport=port, flags='R'), verbose=False)
            return "OPEN"
        elif resp[scapy.TCP].flags == 0x14:
            return "CLOSED"
    return "unknown"


def fin_scan(ip, port, timeout):
    pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags='F')
    resp = scapy.sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return "OPEN|FILTERED"
    elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 0x14:
        return "CLOSED"
    return "unknown"


def ack_scan(ip, port, timeout):
    pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags='A')
    resp = scapy.sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return "FILTERED"
    elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 0x4:
        return "UNFILTERED"
    return "unknown"


def xmas_scan(ip, port, timeout):
    pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags='FPU')
    resp = scapy.sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return "OPEN|FILTERED"
    elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == 0x14:
        return "CLOSED"
    return "unknown"


# =========================
# PORT WORKER (THREADED)
# =========================
def port_worker(q, ip, scan_func, timeout, scan_type):
    while not q.empty():
        port = q.get()
        result = scan_func(ip, port, timeout)

        # ✅ Filter CLOSED ports for specific scans
        if scan_type in ["syn", "fin", "xmas"]:
            if result != "CLOSED":
                print(f"{port}: {result}")
        else:
            # ACK scan still shows all meaningful results
            print(f"{port}: {result}")

        q.task_done()


# =========================
# PORT SCAN WRAPPER
# =========================
def port_scan(ip, ports, scan_type, timeout, threads):
    print(R, f"Starting {scan_type.upper()} scan...", W)

    scan_func = {
        "syn": syn_scan,
        "fin": fin_scan,
        "ack": ack_scan,
        "xmas": xmas_scan
    }[scan_type]

    q = queue.Queue()
    for port in ports:
        q.put(port)

    for _ in range(threads):
        t = threading.Thread(target=port_worker, args=(q, ip, scan_func, timeout, scan_type))
        t.daemon = True
        t.start()

    q.join()
    print()


# =========================
# PORT PARSER
# =========================
def parse_ports(port_str, all_ports=False):
    if all_ports:
        return list(range(1, 65536))

    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")

    parser.add_argument("-m", "--mode", required=True,
                        choices=["arp", "icmp", "port"])

    parser.add_argument("-t", "--target")
    parser.add_argument("--threads", type=int, default=10)

    # PORT OPTIONS
    parser.add_argument("-p", "--ports", help="e.g. 22,80 or 1-1000")
    parser.add_argument("--all-ports", action="store_true")
    parser.add_argument("--scan-type", choices=["syn","fin","ack","xmas"], default="syn")
    parser.add_argument("--timeout", type=float, default=1)

    args = parser.parse_args()

    if args.mode == "arp":
        arp_scan(args.target)

    elif args.mode == "icmp":
        icmp_scan(args.target, args.threads)

    elif args.mode == "port":
        ports = parse_ports(args.ports, args.all_ports)
        port_scan(args.target, ports, args.scan_type, args.timeout, args.threads)


if __name__ == "__main__":
    main()