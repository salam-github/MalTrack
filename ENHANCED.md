Mal Track
=========

"Even the lion has to defend himself against flies."

Objective
---------

The goal of this project is to understand the basic operation of a computer virus in a Windows environment and simple methods to eradicate them.

Overview
--------

Mal Track is a Python-based tool designed to detect, track, and kill malicious processes on a Windows machine. It also provides functionality to update a local database of known malicious file hashes from MalwareBazaar and manage startup programs in Windows.

Features
--------

-   **Process Scanning**: Scans running processes for known malicious files and heuristically suspicious behavior.
-   **Database Update**: Fetches the latest malicious file hashes from MalwareBazaar CSV and updates the local database.
-   **IP Address Detection**: Identifies suspicious IP addresses associated with malicious processes.
-   **Process Termination**: Allows users to terminate malicious processes.
-   **Startup Management**: Removes malicious files from Windows startup programs.
-   **System Snapshot**: Take a snapshot of system files and registry keys.
-   **Integrity Check**: Compare the current state against a previous snapshot to detect changes.
-   **Process Monitoring**: Monitor newly spawned processes and identify unrecognized ones.
-   **Network Traffic Capture**: Capture network traffic and identify new, unrecognized IP addresses.

How It Works
------------

1.  **Detection**:

    -   **Known Malicious Files**: Uses a local database of known malicious file hashes to identify malicious processes.
    -   **Heuristic Checks**: Performs heuristic checks based on file names and paths to identify suspicious behavior.
2.  **Tracking**:

    -   Monitors active network connections of suspicious processes to detect potentially malicious IP addresses.
3.  **Termination**:

    -   Provides an option to terminate identified malicious processes and remove them from startup.
4.  **Snapshots and Monitoring**:

    -   **System Snapshot**: Takes snapshots of important system files and registry keys.
    -   **Integrity Check**: Compares current system state with previous snapshots to detect unauthorized changes.
    -   **Process Monitoring**: Monitors for newly spawned processes.
    -   **Network Traffic Capture**: Captures and analyzes network traffic for suspicious activity.

How to Run
----------

### Prerequisites

-   Python 3.x
-   Required Python packages:

    sh

    Copy code

    `pip install psutil requests tqdm`

-   `tshark` installed and added to the system PATH. Download and install from the [Wireshark website](https://www.wireshark.org/).

### Running the Program

1.  **Clone the Repository**:

    sh

    Copy code

    `git clone https://github.com/yourusername/mal_track.git
    cd mal_track`

2.  **Run the Script**:

    sh

    Copy code

    `python mal_track.py`

3.  **Choose an Option**:

    -   **Option 1**: Scan for malware.
    -   **Option 2**: Update local database from MalwareBazaar CSV.
    -   **Option 3**: Take a snapshot of system files and registry keys.
    -   **Option 4**: Check system integrity against a snapshot.
    -   **Option 5**: Monitor newly spawned processes.
    -   **Option 6**: Capture network traffic.

How IP Addresses Are Detected
-----------------------------

-   The program scans the network connections of identified suspicious processes to gather associated IP addresses. Only IP addresses from suspicious processes are reported.

Managing Startup Programs in Windows
------------------------------------

-   **Windows Registry**: The program interacts with the Windows registry to manage startup programs.
    -   **Registry Keys**:
        -   `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
        -   `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
        -   `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
        -   `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
-   **Removing Startup Entries**: If a suspicious process is terminated, its associated startup entries are also removed from these registry keys.

Script Details
--------------

### `update_local_database_from_csv()`

-   Downloads the latest CSV file containing malicious file hashes from MalwareBazaar.
-   Extracts the CSV file from the downloaded zip file.
-   Parses the CSV to update the local database of known malicious file hashes.

### `detect_suspicious_processes()`

-   Iterates through running processes.
-   Checks each process against the local database of known malicious hashes.
-   Performs heuristic checks for suspicious keywords in file paths.
-   Uses a progress bar to provide feedback during the scan.

### `kill_malware_process(pid)`

-   Terminates a process by its PID.

### `remove_from_startup(exe_path)`

-   Removes entries associated with the given executable path from Windows startup registry keys.

### `take_system_snapshot(full_check)`

-   Takes a snapshot of system files and optionally registry keys.
-   Saves the snapshot to a JSON file.

### `check_integrity(snapshot_file)`

-   Compares the current system state against a previous snapshot to detect changes.
-   Reports added, removed, and modified files and registry keys.

### `monitor_processes(duration)`

-   Monitors newly spawned processes for a specified duration.
-   Reports new processes that are detected.

### `capture_packets(duration, flt)`

-   Captures network packets for a specified duration using `tshark`.
-   Saves the captured packets to a file.

### `take_memory_snapshot(duration)`

-   Takes a snapshot of currently running processes over a specified duration.
-   Saves the snapshot to a JSON file.

### `take_connections_snapshot(duration, flt)`

-   Captures network packets for a specified duration.
-   Uses a filter to capture specific packets and saves the captured packets to a file.

Troubleshooting
---------------

-   Ensure `tshark` is installed and added to the system PATH.
-   Check for necessary permissions if the script reports permission errors.
-   Update the local database regularly to ensure the latest malware definitions are used.
