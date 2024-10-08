import winreg
import os
from tqdm import tqdm
from config import load_config

def remove_from_startup(malware_names, progress_callback=None):
    startup_key_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ]

    hives = [
        winreg.HKEY_CURRENT_USER,
        winreg.HKEY_LOCAL_MACHINE
    ]

    for hive in hives:
        for malware in malware_names:
            for key_path in startup_key_paths:
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as startup_key:
                        try:
                            winreg.DeleteValue(startup_key, malware)
                            message = f"'{malware}' startup entry removed successfully from {key_path}."
                            print(message)
                            if progress_callback:
                                progress_callback({"message": message})
                        except FileNotFoundError:
                            message = f"'{malware}' startup entry not found in {key_path}."
                            print(message)
                            if progress_callback:
                                progress_callback({"message": message})
                except Exception as e:
                    error_message = f"Error: {e}"
                    print(error_message)
                    if progress_callback:
                        progress_callback({"message": error_message})

def delete_registry_keys_associated_with_process(file_path, progress_callback=None):
    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunNotification",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ]

    hives = [
        winreg.HKEY_CURRENT_USER,
        winreg.HKEY_LOCAL_MACHINE
    ]

    for hive in hives:
        for path in registry_paths:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_WRITE) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            if file_path in value_data:
                                winreg.DeleteValue(key, value_name)
                                message = f"Registry entry '{value_name}' removed from {path}."
                                print(message)
                                if progress_callback:
                                    progress_callback({"message": message})
                            else:
                                i += 1
                        except OSError:
                            break
            except Exception as e:
                error_message = f"Error accessing registry path {path}: {e}"
                print(error_message)
                if progress_callback:
                    progress_callback({"message": error_message})

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
