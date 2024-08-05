import winreg
import os
from tqdm import tqdm
from config import load_config

def delete_empty_key(root_key, sub_key):
    """Delete a registry key if it is empty."""
    try:
        with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_ALL_ACCESS) as reg_key:
            # Check if the key is empty
            try:
                if winreg.EnumValue(reg_key, 0):
                    return  # Key is not empty
            except OSError:
                pass  # Key is empty

            try:
                if winreg.EnumKey(reg_key, 0):
                    return  # Key has subkeys
            except OSError:
                pass  # No subkeys

        # If we reached here, the key is empty
        winreg.DeleteKey(root_key, sub_key)
        print(f"Deleted empty registry key: {sub_key}")
    except FileNotFoundError:
        print(f"Registry key not found: {sub_key}")
    except PermissionError:
        print(f"Access denied to registry key: {sub_key}. Please run the script as an administrator.")
    except Exception as e:
        print(f"Error deleting registry key {sub_key}: {e}")

def remove_from_startup(exe_path):
    """Remove the malware from startup."""
    keys_to_check = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]

    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        root_key_name = "HKEY_LOCAL_MACHINE" if root_key == winreg.HKEY_LOCAL_MACHINE else "HKEY_CURRENT_USER"
        for key in keys_to_check:
            full_key_path = f"{root_key_name}\\{key}"
            try:
                reg_key = winreg.OpenKey(root_key, key, 0, winreg.KEY_ALL_ACCESS)
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        print(f"Checking value: {value_name} -> {value_data} in {full_key_path}")
                        if exe_path.lower() in value_data.lower():
                            winreg.DeleteValue(reg_key, value_name)
                            print(f"Removed {value_name} from startup key: {full_key_path}")
                        else:
                            i += 1
                    except OSError:
                        print(f"No more values in key: {full_key_path}")
                        break
            except FileNotFoundError:
                print(f"Registry key not found: {full_key_path}")
                continue
            except PermissionError:
                print(f"Access denied to registry key: {full_key_path}. Please run the script as an administrator.")
            except Exception as e:
                print(f"Error accessing registry key {full_key_path}: {e}")

            # Delete the key if it is empty
            delete_empty_key(root_key, key)

def delete_registry_keys_associated_with_process(process_name):
    """Delete registry keys associated with the given process name."""
    try:
        with open("registry_keys.log", "r") as log_file:
            registry_keys = log_file.readlines()
        for sub_key in registry_keys:
            sub_key = sub_key.strip()
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub_key)
                print(f"Deleted registry key: {sub_key}")
            except FileNotFoundError:
                print(f"Registry key not found: {sub_key}")
    except FileNotFoundError:
        print("Registry keys log file not found.")

def collect_registry():
    """Collect registry values."""
    config = load_config()
    registry_snapshot = {}
    registry_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    progress_bar = tqdm(desc="Collecting registry keys", unit="key")

    for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        root_key_name = "HKEY_LOCAL_MACHINE" if root_key == winreg.HKEY_LOCAL_MACHINE else "HKEY_CURRENT_USER"
        for key in registry_keys:
            full_key_path = f"{root_key_name}\\{key}"
            try:
                reg_key = winreg.OpenKey(root_key, key)
                values = {}
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(reg_key, i)
                        values[value_name] = value_data
                        i += 1
                    except OSError:
                        break
                registry_snapshot[full_key_path] = values
            except FileNotFoundError:
                continue
            progress_bar.update(1)
    
    progress_bar.close()
    return registry_snapshot
