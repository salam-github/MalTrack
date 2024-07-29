import psutil
import subprocess
import socket
import struct
import os
import time

def capture_packets(duration, flt):
    """Capture network packets for a specified duration on Windows."""
    print(f"Capturing packets for {duration} seconds with filter {flt}...")

    # Create a raw socket and bind it to the public interface
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((socket.gethostname(), 0))

    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    start_time = time.time()
    packets = []

    while True:
        # Capture packets for the specified duration
        if time.time() - start_time > duration:
            break
        packet = conn.recvfrom(65565)
        packets.append(packet[0])  # We only need the packet data, not the address

    # Disable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    print("Packet capture completed.")
    return packets

def extract_ips_from_packets(packets):
    """Extract IP addresses from captured packets."""
    ips = {"incoming": set(), "outgoing": set()}

    for packet in packets:
        # Unpack the packet to get the IP header
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extract source and destination IP addresses
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])
        
        ips["outgoing"].add(src_ip)
        ips["incoming"].add(dest_ip)

    return ips

def get_suspicious_ips(pids):
    """Get IP addresses associated with suspicious processes."""
    suspicious_ips = set()
    for pid in pids:
        try:
            p = psutil.Process(pid)
            connections = p.connections(kind='inet')
            for conn in connections:
                if conn.raddr:
                    suspicious_ips.add(conn.raddr.ip)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_ips
