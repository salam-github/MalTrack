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
- **Integrity Check**: Compares the current system state with a snapshot to detect changes.
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

    `pip install psutil requests tqdm tkinter`

### Running the Program

1. **Clone the Repository**:

    `git clone https://github.com/salam-github/MalTrack.git
    cd MalTrack`

2. **Run the Script**:

    `python elevate.py`

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
  - Uses raw sockets to capture packets for a specified duration and filter.

Managing Startup Programs in Windows
------------------------------------

### Explanation

The program interacts with the Windows registry to manage startup programs. It checks specific registry keys where programs are listed to start when Windows boots up. These keys include:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

### How It Works

1. **Detecting Startup Entries**: When a process is flagged as malicious, the program checks these registry keys for any entries associated with the malicious process.
2. **Removing Entries**: If such entries are found, they are deleted from the registry to prevent the malicious process from starting automatically on the next system boot.

### Example

If a process `mal-sim.exe` is detected and flagged as malicious, the program will:

- Search through the mentioned registry keys for any entry that includes `mal-sim.exe`.
- Delete these entries to remove `mal-sim.exe` from the startup programs.

Getting the IP of the Attacker from the Malware
-----------------------------------------------

### Explanation

The program can identify suspicious IP addresses by monitoring the network connections of processes flagged as malicious.

### How It Works

1. **Process Scanning**: When a process is detected as suspicious, the program retrieves all network connections associated with this process.
2. **Extracting IPs**: It collects the remote IP addresses (IP addresses of the other end of the connection) from these connections.
3. **Reporting**: These IP addresses are then reported as potentially malicious or suspicious, indicating where the flagged process is communicating.

### Example

If `mal-sim.exe` is flagged as suspicious, the program will:

- Retrieve network connections of `mal-sim.exe`.
- Collect the IP addresses from these connections.
- Report these IP addresses as suspicious.

How This Program Works
----------------------

### Step-by-Step Explanation

1. **Elevate Privileges**: The program starts with elevated privileges to ensure it has the necessary permissions to scan and modify system settings.
2. **GUI Interface**: The main GUI provides various functionalities like quick scan, full scan, database update, snapshot, etc.
3. **Process Scanning**: When a scan is initiated, the program checks all running processes against a local database of known malicious hashes and performs heuristic checks.
4. **Flagging Suspicious Processes**: If a process is found to be suspicious, it is flagged, and details are displayed in the GUI.
5. **Terminating Processes**: Users can choose to terminate flagged processes through the GUI.
6. **Managing Startup Entries**: For terminated processes, associated startup entries are removed from the registry.
7. **Snapshot and Integrity Check**: Users can take snapshots of system files and registry keys, and later compare the current state with a saved snapshot to detect changes.
8. **Monitoring Processes**: The program can monitor newly spawned processes for a specified duration.
9. **Capturing Network Traffic**: Users can capture network traffic to identify suspicious connections, specifying filters and duration for the capture.

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
