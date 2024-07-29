Mal Track
=========

"Even the lion has to defend himself against flies."

Objective
---------

The goal of this project is to understand the basic operation of a computer virus in a Windows environment and simple methods to eradicate them.

Overview
--------

Mal Track is a Python-based tool designed to detect, track, and kill malicious processes on a Windows machine. It also provides functionality to update a local database of known malicious file hashes from MalwareBazaar, manage startup programs in Windows, take system snapshots, and monitor network traffic.

Features
--------

- **Process Scanning**: Scans running processes for known malicious files and heuristically suspicious behavior.
- **Database Update**: Fetches the latest malicious file hashes from MalwareBazaar CSV and updates the local database.
- **IP Address Detection**: Identifies suspicious IP addresses associated with malicious processes.
- **Process Termination**: Allows users to terminate malicious processes.
- **Startup Management**: Removes malicious files from Windows startup programs.
- **Snapshot**: Takes a snapshot of system files and registry keys for integrity checking.
- **Integrity Check**: Compares current system state with a snapshot to detect changes.
- **Process Monitoring**: Monitors newly spawned processes.
- **Network Traffic Capture**: Captures network traffic to identify suspicious connections.

How It Works
------------

### Detection

1. **Known Malicious Files**: Uses a local database of known malicious file hashes to identify malicious processes.
2. **Heuristic Checks**: Performs heuristic checks based on file names and paths to identify suspicious behavior.

### Tracking

1. Monitors active network connections of identified suspicious processes to detect potentially malicious IP addresses.

### Termination

1. Provides an option to terminate identified malicious processes and remove them from startup.

### Snapshot and Integrity Check

1. **Snapshot**: Takes a snapshot of system files and registry keys.
2. **Integrity Check**: Compares the current system state with a previously taken snapshot to detect changes.

### Network Traffic Capture

1. Captures network traffic based on user-defined filters and duration.

How to Run
----------

### Prerequisites

- Python 3.x

- Required Python packages:

    sh

    Copy code

    `pip install psutil requests tqdm tkinter`

### Running the Program

1. **Clone the Repository**:

    sh

    Copy code

    `git clone https://github.com/yourusername/mal_track.git
    cd mal_track`

2. **Run the Script**:

    sh

    Copy code

    `python gui.py`

3. **GUI Usage**:

    - **Quick Scan**: Perform a quick scan of the system for malware.
    - **Full Scan**: Perform a comprehensive scan of the system for malware.
    - **Update DB**: Update the local database with the latest malicious hashes from MalwareBazaar.
    - **Take Snapshot**: Take a snapshot of system files and registry keys.
    - **Check Integrity**: Check the system integrity against a previously taken snapshot.
    - **Monitor Processes**: Monitor newly spawned processes for a specified duration.
    - **Capture Traffic**: Capture network traffic with specified filters.
    - **Add to Safe List**: Add a file's hash to the safe list.

Detailed Description of Features
--------------------------------

### Process Scanning

- **Function**: Scans running processes against a database of known malicious hashes and heuristically detects suspicious processes.
- **How**:
  - It iterates through running processes and checks their file hashes.
  - If the hash matches a known malicious hash, it flags the process.
  - Heuristically, it looks for suspicious keywords in file paths.

### Database Update

- **Function**: Fetches the latest malicious file hashes from MalwareBazaar CSV.
- **How**:
  - Downloads the CSV file, extracts it, and updates the local database with new hashes.

### IP Address Detection

- **Function**: Identifies suspicious IP addresses associated with malicious processes.
- **How**:
  - Monitors network connections of flagged processes and collects associated IP addresses.

### Process Termination

- **Function**: Allows users to terminate malicious processes.
- **How**:
  - Provides an option in the GUI to kill flagged processes.

### Startup Management

- **Function**: Removes malicious files from Windows startup programs.
- **How**:
  - Checks common startup registry keys and removes entries associated with flagged processes.

### Snapshot and Integrity Check

- **Snapshot**:
  - Takes a snapshot of current system files and registry keys.
  - Saves the snapshot for later comparison.
- **Integrity Check**:
  - Compares the current system state with a saved snapshot.
  - Identifies added, removed, or modified files and registry keys.

### Network Traffic Capture

- **Function**: Captures network traffic to identify suspicious connections.
- **How**:
  - Uses `tshark` to capture packets based on user-defined filters and duration.

Managing Startup Programs in Windows
------------------------------------

- **Windows Registry**: The program interacts with the Windows registry to manage startup programs.
  - **Registry Keys**:
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
    - `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    - `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- **Removing Startup Entries**: If a suspicious process is terminated, its associated startup entries are also removed from these registry keys.

Contributing
------------

If you would like to contribute to Mal Track, please follow these steps:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

License
-------

This project is licensed under the MIT License.
