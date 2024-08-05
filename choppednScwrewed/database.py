import json
import os
import requests
import csv
import zipfile
from io import BytesIO, TextIOWrapper
from tqdm import tqdm
from pathlib import Path
from config import DATABASE_FILE, CSV_URL
from hashing import calculate_file_hash
from utils import calculate_file_hash

WHITELIST_FILE = 'whitelist.json'

def load_local_database():
    """Load the local database of known malicious hashes."""
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, 'r') as file:
            return set(json.load(file))
    return set()

def load_whitelist():
    """Load the whitelist of safe file hashes."""
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as file:
            return set(json.load(file))
    return set()

def save_whitelist(hashes):
    """Save the whitelist of safe file hashes."""
    with open(WHITELIST_FILE, 'w') as file:
        json.dump(list(hashes), file)

def add_to_whitelist(file_path):
    """Add a file's hash to the whitelist."""
    whitelist = load_whitelist()
    file_hash = calculate_file_hash(file_path)
    whitelist.add(file_hash)
    save_whitelist(whitelist)
    print(f"Added {file_path} to whitelist.")

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

def is_known_malicious(file_path):
    """Check if the file hash is in the local database of known malicious hashes."""
    local_hashes = load_local_database()
    whitelist = load_whitelist()
    file_hash = calculate_file_hash(file_path)
    return file_hash in local_hashes and file_hash not in whitelist
