import os
import psutil
import time
import subprocess
import re
from database import is_known_malicious, load_whitelist, add_to_whitelist
from utils import calculate_file_hash  # Import the calculate_file_hash function
from registry import remove_from_startup, delete_registry_keys_associated_with_process  # Import the necessary functions

# List of known malicious processes
KNOWN_MALICIOUS_PROCESSES = [
    "calc.exe",
    "taskmgr.exe",
    "mal-sim.exe",
    "mal-sim.dll",
    "mal sim"
]

def heuristic_check(file_path):
    """Perform basic heuristic checks on the file."""
    suspicious_keywords = ['malware', 'virus', 'trojan', 'backdoor']
    for keyword in suspicious_keywords:
        if keyword in file_path.lower():
            return 50
    return 0

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
                process_name = os.path.basename(file_path)
                
                # Check against known malicious processes
                if process_name in KNOWN_MALICIOUS_PROCESSES:
                    sus_score = 100
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
                    if progress_callback:
                        progress_callback({"message": f"Detected known malicious process: {process_name} (PID: {process.info['pid']}), "
                                                      f"File: {file_path}, Suspicion Score: {sus_score}%",
                                           "current": index + 1, "total": total_processes, "process_info": suspicious_process})
                    continue

                file_hash = calculate_file_hash(file_path)
                if file_hash in safe_hashes:
                    if progress_callback:
                        progress_callback({"message": f"Skipping whitelisted process: {process.info['name']} (PID: {process.info['pid']}), File: {file_path}",
                                          "current": index + 1, "total": total_processes, "process_name": process.info['name']})
                    continue  # Skip whitelisted files

                sus_score = heuristic_check(file_path)
                if is_known_malicious(file_path):
                    sus_score = 100

                if sus_score > 0:
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
                    add_to_whitelist(file_path, process.info['name'])  # Add safe files to whitelist
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
    """Kill the malware process and remove associated registry keys."""
    try:
        process = psutil.Process(pid)
        file_path = process.exe()  # Get the executable path before terminating the process
        process_name = process.name()
        process.terminate()
        process.wait()  # Wait for the process to be terminated

        print(f"Killed malware process with PID {pid}")

        # Remove associated registry keys
        remove_from_startup(file_path)
        delete_registry_keys_associated_with_process(file_path)

        # Remove the malware file
        remove_malware_files(file_path)

        # Identify attacker IP
        identify_attacker_ip(file_path)

        return True
    except Exception as e:
        print(f"Failed to kill malware process: {e}")
        return False

def remove_malware_files(file_path):
    try:
        os.remove(file_path)
        print(f"Removed malware file: {file_path}")
    except Exception as e:
        print(f"Failed to remove malware file: {e}")

def identify_attacker_ip(file_path):
    try:
        with open(file_path, "rb") as f:
            strings = re.findall(b"([\x20-\x7E]{4,})", f.read())
            for s in strings:
                decoded_string = s.decode("utf-8")
                match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", decoded_string)
                if match:
                    print(f"Potential attacker IP: {match.group()}")
    except OSError as e:
        print(f"Failed to identify attacker IP: {e}")

def monitor_new_processes(duration):
    """Monitor newly spawned processes for a specified duration."""
    print("Monitoring newly spawned processes...")
    initial_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))

    time.sleep(duration)

    current_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))
    new_processes = current_processes - initial_processes

    new_process_details = []
    for pid in new_processes:
        try:
            p = psutil.Process(pid)
            process_info = f"New process detected: {p.name()} (PID: {pid}), Path: {p.exe()}"
            print(process_info)
            new_process_details.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return new_process_details
