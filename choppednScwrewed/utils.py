import hashlib
import psutil

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def kill_malware_process(pid):
    """Kill the malware process."""
    try:
        psutil.Process(pid).terminate()
        print(f"Killed malware process with PID {pid}")
        return True
    except Exception as e:
        print(f"Failed to kill malware process: {e}")
        return False
