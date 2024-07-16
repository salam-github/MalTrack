import psutil
import winreg
import socket
import os
import hashlib
import requests
import json
import csv
import zipfile
from io import BytesIO, TextIOWrapper
from tqdm import tqdm
import configparser
import time
from datetime import datetime
import subprocess

# Path to the local database file
DATABASE_FILE = 'malware_hashes.json'
CSV_URL = "https://bazaar.abuse.ch/export/csv/full/"
CONFIG_FILE = 'maltrack.conf'

# Load configuration
config = configparser.ConfigParser()
if os.path.exists(CONFIG_FILE):
    config.read(CONFIG_FILE)
else:
    config['SCAN'] = {'paths': 'C:\\Windows\\System32, C:\\Users', 
                      'exclude_patterns': 'DumpStack.log, DumpStack.log.tmp, hiberfil.sys, swapfile.sys',
                      'registry_keys': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'}
    config['VIRUSTOTAL'] = {'api_key': ''}
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def load_local_database():
    """Load the local database of known malicious hashes."""
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, 'r') as file:
            return set(json.load(file))
    return set()

def save_local_database(hashes):
    """Save the local database of known malicious hashes."""
    with open(DATABASE_FILE, 'w') as file:
        json.dump(list(hashes), file)

def update_local_database_from_csv():
    """Fetch the latest malicious file hashes from MalwareBazaar CSV and update the local database."""
    response = requests.get(CSV_URL, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 Kilobyte

    progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True)
    zip_content = BytesIO()
    for data in response.iter_content(block_size):
        progress_bar.update(len(data))
        zip_content.write(data)
    progress_bar.close()

    if response.status_code == 200:
        with zipfile.ZipFile(zip_content) as z:
            csv_filename = z.namelist()[0]  # Assuming there's only one CSV file in the zip
            with z.open(csv_filename) as csvfile:
                local_hashes = load_local_database()
                new_hashes = set()
                csv_reader = csv.reader(TextIOWrapper(csvfile, 'utf-8'))
                next(csv_reader)  # Skip header line
                for row in csv_reader:
                    sha256_hash = row[0]
                    new_hashes.add(sha256_hash)
                
                if new_hashes:
                    local_hashes.update(new_hashes)
                    save_local_database(local_hashes)
                    print(f"\nUpdated local database with {len(new_hashes)} new hashes from CSV.")
                else:
                    print("No new hashes were found in the CSV file.")
    else:
        print("Failed to download the CSV file from MalwareBazaar.")

def is_known_malicious(file_path, local_hashes):
    """Check if the file hash is in the local database of known malicious hashes."""
    file_hash = calculate_file_hash(file_path)
    return file_hash in local_hashes

def heuristic_check(file_path):
    """Perform basic heuristic checks on the file."""
    suspicious_keywords = ['malware', 'virus', 'trojan', 'backdoor']
    for keyword in suspicious_keywords:
        if keyword in file_path.lower():
            return True
    return False

def detect_suspicious_processes(local_hashes):
    """Detect suspicious processes using local heuristic checks and local database."""
    suspicious_processes = []
    processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
    progress_bar = tqdm(total=len(processes), unit='process', desc='Scanning Processes')
    for process in processes:
        try:
            file_path = process.info['exe']
            if file_path and os.path.isfile(file_path):  # Ensure file_path is valid
                if is_known_malicious(file_path, local_hashes) or heuristic_check(file_path):
                    sus_score = 100 if is_known_malicious(file_path, local_hashes) else 50
                    suspicious_processes.append((process.info['pid'], process.info['name'], file_path, sus_score))
                    print(f"Detected suspicious process: {process.info['name']} (PID: {process.info['pid']}), "
                          f"File: {file_path}, Suspicion Score: {sus_score}%")
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError) as e:
            print(f"Error processing {process.info['name']}: {e}")
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

def remove_from_startup(exe_path):
    """Remove the malware from startup."""
    keys_to_check = config['SCAN']['registry_keys'].split(',')
    
    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for key in keys_to_check:
            try:
                reg_key = winreg.OpenKey(root_key, key.strip(), 0, winreg.KEY_ALL_ACCESS)
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        if exe_path.lower() in value_data.lower():
                            winreg.DeleteValue(reg_key, value_name)
                            print(f"Removed {exe_path} from startup key: {key.strip()}")
                        else:
                            i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                continue

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

def collect_files():
    """Collect hashes of files in the specified directory."""
    file_hashes = {}
    scan_paths = config['SCAN']['paths'].split(',')
    exclude_patterns = config['SCAN']['exclude_patterns'].split(',')
    progress_bar = tqdm(desc="Collecting file hashes", unit="file")

    for scan_path in scan_paths:
        for root, dirs, files in os.walk(scan_path.strip()):
            for file in files:
                file_path = os.path.join(root, file)
                if any(pattern in file_path for pattern in exclude_patterns):
                    continue
                try:
                    file_hashes[file_path] = calculate_file_hash(file_path)
                except PermissionError:
                    print(f"Permission denied: {file_path}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                progress_bar.update(1)
    
    progress_bar.close()
    return file_hashes

def collect_registry():
    """Collect registry values."""
    registry_snapshot = {}
    registry_keys = config['SCAN']['registry_keys'].split(',')
    progress_bar = tqdm(desc="Collecting registry keys", unit="key")

    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for key in registry_keys:
            try:
                reg_key = winreg.OpenKey(root_key, key.strip())
                values = {}
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        values[value_name] = value_data
                        i += 1
                    except OSError:
                        break
                registry_snapshot[f'{root_key}\\{key.strip()}'] = values
            except FileNotFoundError:
                continue
            progress_bar.update(1)
    
    progress_bar.close()
    return registry_snapshot

def collect_processes(duration):
    """Collect process information over a duration."""
    print(f"Collecting processes for {duration} seconds...")
    initial_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'exe'])}

    time.sleep(duration)

    final_processes = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'exe'])}
    new_processes = {pid: info for pid, info in final_processes.items() if pid not in initial_processes}

    return new_processes

def capture_packets(duration, flt):
    """Capture network packets for a specified duration."""
    print(f"Capturing packets for {duration} seconds with filter {flt}...")
    command = f"tshark -a duration:{duration} -f \"{flt}\" -w capture.pcap"
    subprocess.run(command, shell=True)
    print("Packet capture completed.")
    return "capture.pcap"

def take_system_snapshot(full_check):
    try:    
        disk_map = collect_files()
        if not disk_map:
            return False
        with open('file_hashes.json', 'w') as f:
            json.dump(disk_map, f, indent=4)
        if full_check:
            reg_map = collect_registry()
            if not reg_map:
                return False
            with open('registry_snapshot.json', 'w') as f:
                json.dump(reg_map, f, indent=4)
        return True
    except Exception as e:
        print(e)
        return False

def take_memory_snapshot(duration):
    try:
        processes = collect_processes(duration)
        if not processes:
            return False
        with open('processes.json', 'w') as f:
            json.dump(processes, f, indent=4)
        return True 
    except Exception as e:
        print(e)
        return False

def take_connections_snapshot(duration, flt):
    try:
        connections = capture_packets(duration, flt)
        if not connections:
            return False
        return True 
    except Exception as e:
        print(e)
        return False

def check_integrity(snapshot_file):
    """Check the integrity of the system against a previous snapshot."""
    if not os.path.exists(snapshot_file):
        print(f"Snapshot file {snapshot_file} not found.")
        return

    with open(snapshot_file, 'r') as file:
        snapshot = json.load(file)

    current_snapshot = {
        'files': {},
        'registry': {}
    }

    # Check files
    disk_map = collect_files()
    if not disk_map:
        print("Error collecting current file hashes.")
        return
    current_snapshot['files'] = disk_map

    # Compare file snapshots
    file_changes = {
        'added': [],
        'removed': [],
        'modified': []
    }
    for file_path, file_hash in current_snapshot['files'].items():
        if file_path not in snapshot['files']:
            file_changes['added'].append(file_path)
        elif snapshot['files'][file_path] != file_hash:
            file_changes['modified'].append(file_path)
    for file_path in snapshot['files']:
        if file_path not in current_snapshot['files']:
            file_changes['removed'].append(file_path)

    # Check registry
    reg_map = collect_registry()
    if not reg_map:
        print("Error collecting current registry keys.")
        return
    current_snapshot['registry'] = reg_map

    # Compare registry snapshots
    registry_changes = {
        'added': {},
        'removed': {},
        'modified': {}
    }
    for reg_key, values in current_snapshot['registry'].items():
        if reg_key not in snapshot['registry']:
            registry_changes['added'][reg_key] = values
        else:
            for value_name, value_data in values.items():
                if value_name not in snapshot['registry'][reg_key]:
                    if reg_key not in registry_changes['added']:
                        registry_changes['added'][reg_key] = {}
                    registry_changes['added'][reg_key][value_name] = value_data
                elif snapshot['registry'][reg_key][value_name] != value_data:
                    if reg_key not in registry_changes['modified']:
                        registry_changes['modified'][reg_key] = {}
                    registry_changes['modified'][reg_key][value_name] = value_data
    for reg_key, values in snapshot['registry'].items():
        if reg_key not in current_snapshot['registry']:
            registry_changes['removed'][reg_key] = values
        else:
            for value_name in values:
                if value_name not in current_snapshot['registry'][reg_key]:
                    if reg_key not in registry_changes['removed']:
                        registry_changes['removed'][reg_key] = {}
                    registry_changes['removed'][reg_key][value_name] = values[value_name]

    # Print changes
    print("File Changes:")
    print("Added:", file_changes['added'])
    print("Removed:", file_changes['removed'])
    print("Modified:", file_changes['modified'])

    print("Registry Changes:")
    print("Added:", registry_changes['added'])
    print("Removed:", registry_changes['removed'])
    print("Modified:", registry_changes['modified'])

def main():
    print("Welcome to Mal Track")
    print("1. Scan for malware")
    print("2. Update local database from MalwareBazaar CSV")
    print("3. Take a snapshot of system files and registry keys")
    print("4. Check system integrity against a snapshot")
    print("5. Monitor newly spawned processes")
    print("6. Capture network traffic")
    choice = input("Enter your choice (1-6): ")

    if choice == '2':
        update_local_database_from_csv()
        print("Database update completed.")
    elif choice == '3':
        full_check = input("Perform full check including registry? (yes/no): ").lower() == 'yes'
        if take_system_snapshot(full_check):
            print("System snapshot completed.")
        else:
            print("System snapshot failed.")
    elif choice == '4':
        snapshot_file = input("Enter the snapshot file to check against: ")
        check_integrity(snapshot_file)
    elif choice == '5':
        duration = int(input("Enter the monitoring duration in seconds: "))
        if take_memory_snapshot(duration):
            print("Memory snapshot completed.")
        else:
            print("Memory snapshot failed.")
    elif choice == '6':
        duration = int(input("Enter the capture duration in seconds: "))
        flt = input("Enter the capture filter: ")
        if take_connections_snapshot(duration, flt):
            print("Connections snapshot completed.")
        else:
            print("Connections snapshot failed.")
    else:
        print("Starting Mal Track...")

        local_hashes = load_local_database()
        
        suspicious_processes = detect_suspicious_processes(local_hashes)
        if suspicious_processes:
            suspicious_pids = [pid for pid, _, _, _ in suspicious_processes]
            for pid, name, exe_path, sus_score in suspicious_processes:
                user_input = input(f"Do you want to kill the process {name} (PID: {pid})? (yes/no): ")
                if user_input.lower() == 'yes':
                    if kill_malware_process(pid):
                        remove_from_startup(exe_path)
            suspicious_ips = get_suspicious_ips(suspicious_pids)
            if suspicious_ips:
                print(f"Attacker's IP addresses: {', '.join(suspicious_ips)}")
            else:
                print("No suspicious IP addresses detected.")
        else:
            print("No suspicious processes detected.")
        
        print("Mal Track completed.")

if __name__ == "__main__":
    main()
