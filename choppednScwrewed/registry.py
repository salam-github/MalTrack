import winreg
import os
from tqdm import tqdm
from config import load_config

def remove_from_startup(malware_names):
    startup_key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

    for malware in malware_names:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_key_path, 0, winreg.KEY_SET_VALUE) as startup_key:
                try:
                    winreg.DeleteValue(startup_key, malware)
                    print(f"'{malware}' startup entry removed successfully.")
                except FileNotFoundError:
                    print(f"'{malware}' startup entry not found.")
        except Exception as e:
            print(f"Error: {e}")

def delete_registry_keys_associated_with_process(exe_paths):
    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        # Add other registry paths if the malware is known to add keys there
    ]

    for exe_path in exe_paths:
        for path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as key:
                    try:
                        winreg.DeleteValue(key, exe_path)
                        print(f"Registry entry '{exe_path}' removed from {path}.")
                    except FileNotFoundError:
                        print(f"No registry entry for '{exe_path}' found in {path}.")
            except Exception as e:
                print(f"Error accessing registry path {path}: {e}")

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
