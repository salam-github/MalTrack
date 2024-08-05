import re
import socket
import subprocess
import psutil
import os

def identify_attacker_ip(filename):
    filepath = file_location(filename)
    try:
        with open(filepath, "rb") as f:
            strings = re.findall(b"([\x20-\x7E]{4,})", f.read())
            for s in strings:
                decoded_string = s.decode("utf-8")
                match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", decoded_string)
                if match:
                    print(f"Potential attacker IP: {match.group()}")
    except OSError as e:
        print(e)

def file_location(filename):
    try:
        for root, _, files in os.walk("C:\\"):
            if filename in files:
                return os.path.join(root, filename)
    except Exception as e:
        print(f"Error: {e}")

def capture_packets(duration, flt):
    """Capture network packets for a specified duration."""
    command = f"tshark -a duration:{duration} -f \"{flt}\" -w capture.pcap"
    subprocess.run(command, shell=True)
    return "capture.pcap"

def extract_ips_from_packets(pcap_file):
    """Extract IPs from captured packets using tshark."""
    command = f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    ips = {"outgoing": set(), "incoming": set()}
    for line in result.stdout.splitlines():
        src_ip, dst_ip = line.split()
        ips["outgoing"].add(src_ip)
        ips["incoming"].add(dst_ip)
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
