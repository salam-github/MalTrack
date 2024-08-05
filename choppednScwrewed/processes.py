import psutil
import os
from utils import calculate_file_hash

# List of known malicious processes
KNOWN_MALICIOUS_PROCESSES = [
    "malicious1.exe",
    "malicious2.exe",
    "taskmgr.exe"  # Example entry
]

def detect_suspicious_processes(local_hashes, progress_callback=None, scan_type='quick'):
    """Detect suspicious processes using local heuristic checks and local database."""
    suspicious_processes = []
    whitelist = load_whitelist()
    processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']))
    progress_bar = tqdm(total=len(processes), unit='process', desc='Scanning Processes')

    for idx, process in enumerate(processes):
        try:
            file_path = process.info['exe']
            if file_path and os.path.isfile(file_path):  # Ensure file_path is valid
                process_name = os.path.basename(file_path)

                # Check against known malicious processes
                if process_name in KNOWN_MALICIOUS_PROCESSES:
                    sus_score = 100
                    process_info = {
                        'pid': process.info['pid'],
                        'name': process.info['name'],
                        'file_path': file_path,
                        'sus_score': sus_score,
                        'cmdline': process.info['cmdline'],
                        'create_time': process.info['create_time'],
                        'username': process.info['username']
                    }
                    suspicious_processes.append(process_info)
                    if progress_callback:
                        progress_callback({"message": f"Detected known malicious process: {process_name} (PID: {process.info['pid']}), "
                                                      f"File: {file_path}, Suspicion Score: {sus_score}%",
                                           "current": idx + 1, "total": len(processes), "process_info": process_info})
                    continue

                # Skip whitelisted processes in quick scan
                if scan_type == 'quick':
                    file_hash = calculate_file_hash(file_path)
                    if file_hash in whitelist:
                        if progress_callback:
                            progress_callback({"message": f"Skipping whitelisted process: {process_name} (PID: {process.info['pid']}), "
                                                          f"File: {file_path}",
                                               "current": idx + 1, "total": len(processes)})
                        continue

                # Check against local database
                if is_known_malicious(file_path, local_hashes):
                    sus_score = 100
                else:
                    sus_score = heuristic_check(file_path)

                if sus_score > 0:
                    process_info = {
                        'pid': process.info['pid'],
                        'name': process.info['name'],
                        'file_path': file_path,
                        'sus_score': sus_score,
                        'cmdline': process.info['cmdline'],
                        'create_time': process.info['create_time'],
                        'username': process.info['username']
                    }
                    suspicious_processes.append(process_info)
                    if progress_callback:
                        progress_callback({"message": f"Detected suspicious process: {process_name} (PID: {process.info['pid']}), "
                                                      f"File: {file_path}, Suspicion Score: {sus_score}%",
                                           "current": idx + 1, "total": len(processes), "process_info": process_info})

        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError) as e:
            if progress_callback:
                progress_callback({"message": f"Error processing {process.info['name']}: {e}",
                                   "current": idx + 1, "total": len(processes)})

        progress_bar.update(1)
    progress_bar.close()
    return suspicious_processes

def kill_malware_process(pid):
    """Kill the malware process."""
    try:
        psutil.Process(pid).terminate()
        print(f"Killed malware process with PID {pid}")
        return True
    except Exception as e:
        print(f"Failed to kill malware process: {e}")
        return False

def delete_registry_keys_associated_with_process(file_path):
    """Delete registry keys associated with a given file path."""
    keys_to_check = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    ]

    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for key in keys_to_check:
            try:
                reg_key = winreg.OpenKey(root_key, key, 0, winreg.KEY_ALL_ACCESS)
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        if file_path in value_data:
                            winreg.DeleteValue(reg_key, value_name)
                            print(f"Deleted registry key: {key} -> {value_name}")
                        else:
                            i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                continue

def heuristic_check(file_path):
    """Perform basic heuristic checks on the file."""
    suspicious_keywords = ['malware', 'virus', 'trojan', 'backdoor']
    for keyword in suspicious_keywords:
        if keyword in file_path.lower():
            return 50
    return 0

def is_known_malicious(file_path, local_hashes):
    """Check if the file hash is in the local database of known malicious hashes."""
    file_hash = calculate_file_hash(file_path)
    return file_hash in local_hashes
