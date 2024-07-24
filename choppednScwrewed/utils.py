import psutil

def kill_malware_process(pid):
    """Kill the malware process."""
    try:
        psutil.Process(pid).terminate()
        print(f"Killed malware process with PID {pid}")
        return True
    except Exception as e:
        print(f"Failed to kill malware process: {e}")
        return False
