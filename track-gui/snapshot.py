import json
import os
from tqdm import tqdm
from hashing import calculate_file_hash
from registry import collect_registry

def collect_files():
    """Collect hashes of files in the specified directory."""
    config = load_config()
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
