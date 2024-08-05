from database import update_local_database_from_csv, load_local_database, load_whitelist
from processes import detect_suspicious_processes, kill_malware_process, monitor_new_processes
from snapshot import take_system_snapshot, check_integrity
from network import capture_packets, extract_ips_from_packets, get_suspicious_ips
from registry import remove_from_startup

def scan_for_malware(progress_callback=None, scan_type='quick'):
    local_hashes = load_local_database()
    whitelist = load_whitelist()
    suspicious_processes = detect_suspicious_processes(local_hashes, whitelist, progress_callback, quick_scan=(scan_type == 'quick'))
    results = []
    if suspicious_processes:
        suspicious_pids = [pid for pid, _, _, _ in suspicious_processes]
        for pid, name, exe_path, sus_score in suspicious_processes:
            results.append(f"Detected suspicious process: {name} (PID: {pid}), "
                           f"File: {exe_path}, Suspicion Score: {sus_score}%")
            if sus_score > 70:  # Automatically kill for high suspicion score
                if kill_malware_process(pid):
                    remove_from_startup(exe_path)
            else:
                # Ask user to kill for lower suspicion score
                pass  # Implement user interaction logic here
        suspicious_ips = get_suspicious_ips(suspicious_pids)
        if suspicious_ips:
            results.append(f"Attacker's IP addresses: {', '.join(suspicious_ips)}")
        else:
            results.append("No suspicious IP addresses detected.")
    else:
        results.append("No suspicious processes detected.")
    return "\n".join(results), suspicious_processes


def update_database():
    update_local_database_from_csv()
    return "Database update completed."

def take_snapshot(full_check):
    if take_system_snapshot(full_check):
        return "System snapshot completed."
    else:
        return "System snapshot failed."

def check_system_integrity(snapshot_file):
    return check_integrity(snapshot_file)

def monitor_processes(duration):
    new_process_details = monitor_new_processes(duration)
    return "\n".join(new_process_details)

def capture_network_traffic(duration, flt):
    packets = capture_packets(duration, flt)
    ips = extract_ips_from_packets(packets)
    report = "Network Traffic Report:\n\n"
    report += "Outgoing IPs:\n" + "\n".join(ips["outgoing"]) + "\n\n"
    report += "Incoming IPs:\n" + "\n".join(ips["incoming"]) + "\n"
    return report