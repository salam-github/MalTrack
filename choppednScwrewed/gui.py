import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, scrolledtext, ttk
from main import scan_for_malware, update_database, take_snapshot, check_system_integrity, monitor_processes, capture_network_traffic, kill_malware_process
from database import add_to_whitelist
import threading
import time

suspicious_processes = []

def run_in_thread(func, process_name, *args):
    """Run a function in a separate thread and handle the result in the main thread."""
    def wrapper():
        status_label.config(text=f"{process_name} starting...")
        start_time = time.time()
        result = func(*args)
        elapsed_time = time.time() - start_time
        output_text.insert(tk.END, result + "\n", "regular")
        output_text.see(tk.END)
        status_label.config(text=f"{process_name} completed in {elapsed_time:.2f} seconds")

    thread = threading.Thread(target=wrapper)
    thread.start()

def start_malware_scan(scan_type='quick'):
    progress_bar['value'] = 0
    progress_bar['maximum'] = 100  # This will be updated dynamically
    status_label.config(text=f"Starting {scan_type} scan for malware...")
    treeview.delete(*treeview.get_children())  # Clear previous results
    global suspicious_processes
    suspicious_processes = []  # Clear previous results

    def progress_callback(data):
        message = data.get("message", "")
        current = data.get("current")
        total = data.get("total")
        process_info = data.get("process_info")
        
        if message:
            if "Detected suspicious process" in message:
                output_text.insert(tk.END, "\nDetected Suspicious Process:\n", "header")
                output_text.insert(tk.END, message + "\n", "suspicious")
                output_text.see(tk.END)

                if process_info:
                    pid = process_info.get('pid', '')
                    name = process_info.get('name', '')
                    file_path = process_info.get('file_path', '')
                    sus_score = process_info.get('sus_score', '')
                    cmdline = ' '.join(process_info.get('cmdline', []))
                    create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(process_info.get('create_time', 0)))
                    username = process_info.get('username', '')

                    # Print parsed data for debugging
                    print(f"Parsed data: PID={pid}, Name={name}, File Path={file_path}, Suspicion Score={sus_score}, Command Line={cmdline}, Creation Time={create_time}, Username={username}")

                    treeview.insert("", "end", values=(pid, name, file_path, sus_score, cmdline, create_time, username))
            elif "Skipping whitelisted process" in message:
                output_text.insert(tk.END, message + "\n", "whitelist")
                status_label.config(text=message)
            else:
                output_text.insert(tk.END, message + "\n", "regular")
                output_text.see(tk.END)
        if current is not None and total is not None:
            progress_bar['maximum'] = total
            progress_bar['value'] = current
            process_name = data.get("process_name", "")
            if process_name:
                status_label.config(text=f"Scanning process {current} of {total}: {process_name}")
            else:
                status_label.config(text=f"Scanning process {current} of {total}")
            if current == total:
                status_label.config(text="Scan completed")
        else:
            status_label.config(text=f"Scanning process {current} of {total}")

    def scan():
        status_label.config(text="Scan in progress...")
        result, suspicious_processes_local = scan_for_malware(progress_callback, scan_type)
        output_text.insert(tk.END, result + "\n", "regular")
        output_text.see(tk.END)
        global suspicious_processes
        suspicious_processes = suspicious_processes_local
        if progress_bar['value'] == progress_bar['maximum']:
            status_label.config(text="Scan completed")
        else:
            status_label.config(text="Scan in progress...")

    thread = threading.Thread(target=scan)
    thread.start()

def update_database_gui():
    run_in_thread(update_database, "Database update")

def take_snapshot_gui():
    full_check = messagebox.askyesno("Take Snapshot", "Perform full check including registry?")
    if full_check is not None:
        run_in_thread(take_snapshot, "System snapshot", full_check)

def check_system_integrity_gui():
    snapshot_file = filedialog.askopenfilename(title="Select Snapshot File")
    if snapshot_file:
        run_in_thread(check_system_integrity, "Integrity check", snapshot_file)

def monitor_processes_gui():
    duration = simpledialog.askinteger("Monitor Processes", "Enter the monitoring duration in seconds:")
    if duration:
        run_in_thread(monitor_processes, "Process monitoring", duration)

def capture_network_traffic_gui():
    duration = simpledialog.askinteger("Capture Network Traffic", "Enter the capture duration in seconds:")
    if duration:
        flt = simpledialog.askstring("Capture Network Traffic", "Enter the capture filter:")
        if flt:
            run_in_thread(capture_network_traffic, "Network traffic capture", duration, flt)
        else:
            messagebox.showerror("Capture Network Traffic", "Capture filter is required.")
    else:
        messagebox.showerror("Capture Network Traffic", "Duration is required.")

def inspect_process():
    selected_item = treeview.selection()
    if selected_item:
        process_info = treeview.item(selected_item, 'values')
        details = (
            f"Name: {process_info[1]}\n"
            f"PID: {process_info[0]}\n"
            f"File Path: {process_info[2]}\n"
            f"Suspicion Score: {process_info[3]}%\n"
            f"Command Line: {process_info[4]}\n"
            f"Creation Time: {process_info[5]}\n"
            f"Username: {process_info[6]}"
        )
        messagebox.showinfo("Process Information", details)
    else:
        messagebox.showwarning("Inspect Process", "No process selected")

def kill_selected_process():
    selected_item = treeview.selection()
    if selected_item:
        process_info = treeview.item(selected_item, 'values')
        pid = int(process_info[0])
        if messagebox.askyesno("Kill Process", f"Are you sure you want to kill process {process_info[1]} (PID: {pid})?"):
            if kill_malware_process(pid):
                treeview.delete(selected_item)
                messagebox.showinfo("Kill Process", f"Process {process_info[1]} (PID: {pid}) killed successfully.")
            else:
                messagebox.showerror("Kill Process", f"Failed to kill process {process_info[1]} (PID: {pid}).")
    else:
        messagebox.showwarning("Kill Process", "No process selected")

def add_safe_hash_gui():
    file_path = filedialog.askopenfilename(title="Select File to Trust")
    if file_path:
        add_to_whitelist(file_path)
        messagebox.showinfo("Add Safe Hash", f"File {file_path} added to safe list.")

# Create the main window
root = tk.Tk()
root.title("Mal Track")
root.geometry("1000x700")  # Set the window size

# Apply a modern style
style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Helvetica', 10), padding=10, relief="flat", background="#4CAF50", foreground="white")
style.configure('TLabel', font=('Helvetica', 10))
style.configure('TProgressbar', thickness=20)

# Create and place buttons in a frame
button_frame = ttk.Frame(root)
button_frame.pack(side=tk.TOP, fill=tk.X, pady=10)

buttons = [
    ("Quick Scan", lambda: start_malware_scan('quick')),
    ("Full Scan", lambda: start_malware_scan('full')),
    ("Update DB", update_database_gui),
    ("Take Snapshot", take_snapshot_gui),
    ("Check Integrity", check_system_integrity_gui),
    ("Monitor Processes", monitor_processes_gui),
    ("Capture Traffic", capture_network_traffic_gui),
    ("Add to Safe List", add_safe_hash_gui),
]

for text, command in buttons:
    button = ttk.Button(button_frame, text=text, command=command)
    button.pack(side=tk.LEFT, padx=5)

# Create a scrolled text widget for output
output_frame = ttk.Frame(root)
output_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=10, font=('Helvetica', 10))
output_text.pack(fill=tk.BOTH, expand=True)

# Define tags for styling
output_text.tag_configure("header", font=('Helvetica', 12, 'bold'), foreground="red")
output_text.tag_configure("subheader", font=('Helvetica', 10, 'bold'), foreground="blue")
output_text.tag_configure("suspicious", font=('Helvetica', 10, 'bold'), foreground="orange")
output_text.tag_configure("whitelist", font=('Helvetica', 10, 'italic'), foreground="green")
output_text.tag_configure("regular", font=('Helvetica', 10))

# Create a progress bar
progress_frame = ttk.Frame(root)
progress_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

progress_bar = ttk.Progressbar(progress_frame, orient='horizontal', length=400, mode='determinate')
progress_bar.pack(fill=tk.X)

# Create a status label
status_label = ttk.Label(progress_frame, text="")
status_label.pack(pady=5)

# Create a Treeview for suspicious processes
treeview_frame = ttk.Frame(root)
treeview_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

columns = ("pid", "name", "file_path", "sus_score", "cmdline", "create_time", "username")
treeview = ttk.Treeview(treeview_frame, columns=columns, show='headings')
treeview.heading("pid", text="PID")
treeview.heading("name", text="Name")
treeview.heading("file_path", text="File Path")
treeview.heading("sus_score", text="Suspicion Score")
treeview.heading("cmdline", text="Command Line")
treeview.heading("create_time", text="Creation Time")
treeview.heading("username", text="Username")

treeview.column("pid", width=50)
treeview.column("name", width=150)
treeview.column("file_path", width=250)
treeview.column("sus_score", width=100)
treeview.column("cmdline", width=250)
treeview.column("create_time", width=150)
treeview.column("username", width=150)

treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar to the Treeview
scrollbar = ttk.Scrollbar(treeview_frame, orient="vertical", command=treeview.yview)
treeview.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Create buttons for inspecting and killing processes
action_frame = ttk.Frame(root)
action_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

inspect_button = ttk.Button(action_frame, text="Inspect Process", command=inspect_process)
inspect_button.pack(side=tk.LEFT, padx=10, pady=10)

kill_button = ttk.Button(action_frame, text="Kill Process", command=kill_selected_process)
kill_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Run the main loop
root.mainloop()
