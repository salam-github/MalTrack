import os
import psutil
import time
from database import is_known_malicious, load_whitelist, add_to_whitelist
from utils import calculate_file_hash  # Import the calculate_file_hash function

def heuristic_check(file_path):
    """Perform basic heuristic checks on the file."""
    suspicious_keywords = ['malware', 'virus', 'trojan', 'backdoor', 'calc.exe', 'taskmgr.exe']
    for keyword in suspicious_keywords:
        if keyword in file_path.lower():
            return True
    return False

def detect_suspicious_processes(local_hashes, progress_callback=None, quick_scan=False):
    """Detect suspicious processes using local heuristic checks and local database."""
    safe_hashes = load_whitelist() if quick_scan else set()
    suspicious_processes = []
    processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']))
    total_processes = len(processes)

    for index, process in enumerate(processes):
        try:
            file_path = process.info['exe']
            if file_path and os.path.isfile(file_path):  # Ensure file_path is valid
                file_hash = calculate_file_hash(file_path)
                if file_hash in safe_hashes:
                    if progress_callback:
                        progress_callback({"message": f"Skipping whitelisted process: {process.info['name']} (PID: {process.info['pid']}), File: {file_path}",
                                          "current": index + 1, "total": total_processes, "process_name": process.info['name']})
                    continue  # Skip whitelisted files

                if is_known_malicious(file_path) or heuristic_check(file_path):
                    sus_score = 100 if is_known_malicious(file_path) else 50
                    suspicious_process = {
                        'pid': process.info['pid'],
                        'name': process.info['name'],
                        'file_path': file_path,
                        'sus_score': sus_score,
                        'cmdline': process.info['cmdline'],
                        'create_time': process.info['create_time'],
                        'username': process.info['username']
                    }
                    suspicious_processes.append(suspicious_process)
                    
                    # Print the suspicious process for debugging
                    print(suspicious_process)

                    if progress_callback:
                        cmdline_str = ' '.join(process.info['cmdline']) if process.info['cmdline'] else 'N/A'
                        progress_callback({"message": f"Detected suspicious process: {process.info['name']} (PID: {process.info['pid']}), "
                                                      f"File: {file_path}, Suspicion Score: {sus_score}%, "
                                                      f"Command Line: {cmdline_str}, "
                                                      f"Creation Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process.info['create_time']))}, "
                                                      f"Username: {process.info['username']}",
                                          "current": index + 1, "total": total_processes, "process_name": process.info['name'],
                                          "process_info": suspicious_process})
                else:
                    add_to_whitelist(file_path)  # Add safe files to whitelist
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError) as e:
            if progress_callback:
                progress_callback({"message": f"Error processing {process.info['name']}: {e}",
                                  "current": index + 1, "total": total_processes, "process_name": process.info['name']})

        if progress_callback:
            progress_callback({"current": index + 1, "total": total_processes, "process_name": process.info['name']})
    if progress_callback:
        progress_callback({"current": total_processes, "total": total_processes})
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

def monitor_processes(duration):
    """Monitor newly spawned processes for a specified duration."""
    print("Monitoring newly spawned processes...")
    initial_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))

    time.sleep(duration)

    current_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))
    new_processes = current_processes - initial_processes

    for pid in new_processes:
        try:
            p = psutil.Process(pid)
            print(f"New process detected: {p.name()} (PID: {pid}), Path: {p.exe()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
