import winreg
from config import load_config

def remove_from_startup(exe_path):
    """Remove the malware from startup."""
    config = load_config()
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

def collect_registry():
    """Collect registry values."""
    config = load_config()
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
