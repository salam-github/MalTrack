import re
import os
import psutil
import subprocess

def file_location(filename):
    """Locate the file path for a given filename."""
    try:
        for root, _, files in os.walk("C:\\"):
            if filename in files:
                return os.path.join(root, filename)
    except Exception as e:
        print(f"Error locating file: {e}")
    return None

def identify_attacker_ip(filename):
    """Identify potential attacker IP addresses in the given file."""
    filepath = file_location(filename)
    if not filepath:
        return "File not found"
    try:
        with open(filepath, "rb") as f:
            strings = re.findall(b"([\x20-\x7E]{4,})", f.read())
            for s in strings:
                decoded_string = s.decode("utf-8")
                match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", decoded_string)
                if match:
                    return f"Potential attacker IP: {match.group()}"
    except OSError as e:
        return f"Error: {e}"
    return "No IP address found"

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

def capture_packets(duration, flt):
    """Capture network packets for a specified duration."""
    capture_file = "capture.pcap"
    command = f"tshark -a duration:{duration} -f \"{flt}\" -w {capture_file}"
    subprocess.run(command, shell=True)
    return capture_file

def extract_ips_from_packets(pcap_file):
    """Extract IP addresses from a packet capture file."""
    ips = {"outgoing": set(), "incoming": set()}
    command = f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        src, dst = line.split()
        ips["outgoing"].add(src)
        ips["incoming"].add(dst)
    return ips
