import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, scrolledtext, ttk
from main import scan_for_malware, update_database, take_snapshot, check_system_integrity, monitor_processes, capture_network_traffic, kill_malware_process
import threading
import time

suspicious_processes = []

def run_in_thread(func, *args):
    """Run a function in a separate thread and handle the result in the main thread."""
    def wrapper():
        result = func(*args)
        output_text.insert(tk.END, result + "\n")
        output_text.see(tk.END)

    thread = threading.Thread(target=wrapper)
    thread.start()

def start_malware_scan():
    progress_bar['value'] = 0
    progress_bar['maximum'] = 100  # This will be updated dynamically
    status_label.config(text="Scanning for malware...")
    listbox.delete(0, tk.END)  # Clear previous results
    global suspicious_processes
    suspicious_processes = []  # Clear previous results

    def progress_callback(message=None, current=None, total=None):
        if message:
            output_text.insert(tk.END, message + "\n")
            output_text.see(tk.END)
            if "Detected suspicious process" in message:
                process_info = message.split(", ")
                listbox.insert(tk.END, process_info)
        if current is not None and total is not None:
            progress_bar['maximum'] = total
            progress_bar['value'] = current
            status_label.config(text=f"Scanning process {current} of {total}")

    def scan():
        result, suspicious_processes_local = scan_for_malware(progress_callback)
        output_text.insert(tk.END, result + "\n")
        output_text.see(tk.END)
        status_label.config(text="Scan completed")
        global suspicious_processes
        suspicious_processes = suspicious_processes_local

    thread = threading.Thread(target=scan)
    thread.start()

def update_database_gui():
    run_in_thread(update_database)

def take_snapshot_gui():
    full_check = messagebox.askyesno("Take Snapshot", "Perform full check including registry?")
    if full_check is not None:
        run_in_thread(take_snapshot, full_check)

def check_system_integrity_gui():
    snapshot_file = filedialog.askopenfilename(title="Select Snapshot File")
    if snapshot_file:
        run_in_thread(check_system_integrity, snapshot_file)

def monitor_processes_gui():
    duration = simpledialog.askinteger("Monitor Processes", "Enter the monitoring duration in seconds:")
    if duration:
        run_in_thread(monitor_processes, duration)

def capture_network_traffic_gui():
    duration = simpledialog.askinteger("Capture Network Traffic", "Enter the capture duration in seconds:")
    if duration:
        flt = simpledialog.askstring("Capture Network Traffic", "Enter the capture filter:")
        if flt:
            run_in_thread(capture_network_traffic, duration, flt)
        else:
            messagebox.showerror("Capture Network Traffic", "Capture filter is required.")
    else:
        messagebox.showerror("Capture Network Traffic", "Duration is required.")

def inspect_process():
    selected_index = listbox.curselection()
    if selected_index:
        process_info = suspicious_processes[selected_index[0]]
        details = (
            f"Name: {process_info['name']}\n"
            f"PID: {process_info['pid']}\n"
            f"File Path: {process_info['file_path']}\n"
            f"Suspicion Score: {process_info['sus_score']}%\n"
            f"Command Line: {' '.join(process_info['cmdline']) if process_info['cmdline'] else 'N/A'}\n"
            f"Creation Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process_info['create_time']))}\n"
            f"Username: {process_info['username']}"
        )
        messagebox.showinfo("Process Information", details)
    else:
        messagebox.showwarning("Inspect Process", "No process selected")

def kill_selected_process():
    selected_index = listbox.curselection()
    if selected_index:
        process_info = suspicious_processes[selected_index[0]]
        pid = process_info['pid']
        if messagebox.askyesno("Kill Process", f"Are you sure you want to kill process {process_info['name']} (PID: {pid})?"):
            if kill_malware_process(pid):
                listbox.delete(selected_index)
                messagebox.showinfo("Kill Process", f"Process {process_info['name']} (PID: {pid}) killed successfully.")
            else:
                messagebox.showerror("Kill Process", f"Failed to kill process {process_info['name']} (PID: {pid}).")
    else:
        messagebox.showwarning("Kill Process", "No process selected")

# Create the main window
root = tk.Tk()
root.title("Mal Track")

# Create and place buttons
buttons = [
    ("Scan for malware", start_malware_scan),
    ("Update local database", update_database_gui),
    ("Take snapshot of system files and registry keys", take_snapshot_gui),
    ("Check system integrity against a snapshot", check_system_integrity_gui),
    ("Monitor newly spawned processes", monitor_processes_gui),
    ("Capture network traffic", capture_network_traffic_gui),
]

for text, command in buttons:
    button = tk.Button(root, text=text, command=command, padx=20, pady=10)
    button.pack(pady=5)

# Create a scrolled text widget for output
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
output_text.pack(pady=10)

# Create a progress bar
progress_bar = ttk.Progressbar(root, orient='horizontal', length=400, mode='determinate')
progress_bar.pack(pady=10)

# Create a status label
status_label = tk.Label(root, text="")
status_label.pack(pady=5)

# Create a listbox for suspicious processes
listbox = tk.Listbox(root, width=100, height=10)
listbox.pack(pady=10)

# Create buttons for inspecting and killing processes
inspect_button = tk.Button(root, text="Inspect Process", command=inspect_process)
inspect_button.pack(side=tk.LEFT, padx=10, pady=10)

kill_button = tk.Button(root, text="Kill Process", command=kill_selected_process)
kill_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Run the main loop
root.mainloop()
