from database import update_local_database_from_csv, load_local_database
from processes import detect_suspicious_processes, kill_malware_process, monitor_new_processes
from snapshot import take_system_snapshot, check_integrity
from network import capture_packets, extract_ips_from_packets, get_suspicious_ips, identify_attacker_ip
from registry import remove_from_startup, delete_registry_keys_associated_with_process

def scan_for_malware(progress_callback=None, scan_type='quick'):
    quick_scan = scan_type == 'quick'
    local_hashes = load_local_database()
    suspicious_processes = detect_suspicious_processes(local_hashes, progress_callback, quick_scan)
    results = []
    all_attacker_ips = []
    
    for process_info in suspicious_processes:
        pid = process_info['pid']
        name = process_info['name']
        exe_path = process_info['file_path']
        sus_score = process_info['sus_score']
        results.append(f"Detected suspicious process: {name} (PID: {pid}), "
                       f"File: {exe_path}, Suspicion Score: {sus_score}%")
        if sus_score > 70:
            if kill_malware_process(pid):
                remove_from_startup([name])  # Use the correct name for the startup entry
                delete_registry_keys_associated_with_process(exe_path)
                results.append(f"Killed malware process: {name} (PID: {pid})")
        else:
            results.append(f"Suspicious process: {name} (PID: {pid}) requires user action.")

        # Identify attacker IP from the file content
        attacker_ips = identify_attacker_ip(exe_path)
        all_attacker_ips.extend(attacker_ips)
    
    suspicious_pids = [p['pid'] for p in suspicious_processes]
    suspicious_ips = get_suspicious_ips(suspicious_pids)
    all_attacker_ips.extend(suspicious_ips)
    
    if all_attacker_ips:
        results.append(f"Attacker's IP addresses: {', '.join(all_attacker_ips)}")
    else:
        results.append("No suspicious IP addresses detected.")
    
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

if __name__ == "__main__":
    print(scan_for_malware())
