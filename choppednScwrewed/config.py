import configparser
import os
from pathlib import Path

CONFIG_FILE = Path.home() / ".maltrack" / "maltrack.conf"
DATABASE_FILE = Path.home() / ".maltrack" / "malware_hashes.json"
CSV_URL = "https://bazaar.abuse.ch/export/csv/full/"

# Ensure the config directory exists
CONFIG_FILE.parent.mkdir(exist_ok=True, parents=True)

def load_config():
    config = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE)
    else:
        config['SCAN'] = {'paths': 'C:\\Windows\\System32, C:\\Users', 
                          'exclude_patterns': 'DumpStack.log, DumpStack.log.tmp, hiberfil.sys, swapfile.sys',
                          'registry_keys': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'}
        config['VIRUSTOTAL'] = {'api_key': ''}
        save_config(config)
    return config

def save_config(config):
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)
