import psutil
import subprocess

def capture_packets(duration, flt):
    """Capture network packets for a specified duration."""
    print(f"Capturing packets for {duration} seconds with filter {flt}...")
    command = f"tshark -a duration:{duration} -f \"{flt}\" -w capture.pcap"
    subprocess.run(command, shell=True)
    print("Packet capture completed.")
    return "capture.pcap"

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
