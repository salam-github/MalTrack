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

# Path to the local database file
DATABASE_FILE = 'malware_hashes.json'
CSV_URL = "https://bazaar.abuse.ch/export/csv/full/"

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
    keys_to_check = [
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    ]
    
    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for key in keys_to_check:
            try:
                reg_key = winreg.OpenKey(root_key, key, 0, winreg.KEY_ALL_ACCESS)
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        if exe_path.lower() in value_data.lower():
                            winreg.DeleteValue(reg_key, value_name)
                            print(f"Removed {exe_path} from startup key: {key}")
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

def main():
    print("Welcome to Mal Track")
    print("1. Scan for malware")
    print("2. Update local database from MalwareBazaar CSV")
    choice = input("Enter your choice (1/2): ")

    if choice == '2':
        update_local_database_from_csv()
        print("Database update completed.")
        return

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
