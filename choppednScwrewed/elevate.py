import ctypes
import sys
import os
import subprocess

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin(script_path):
    """Run the specified script with administrative privileges."""
    try:
        params = f'"{script_path}"'
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if is_admin():
        print("Already running with admin privileges.")
        # Ensure the current working directory is set to the script's directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        # Import and run the main entry point of your GUI here
        import gui
    else:
        print("Attempting to elevate privileges...")
        script_path = os.path.join(os.getcwd(), "gui.py")
        print(f"Relaunching with elevated privileges: {sys.executable} {script_path}")
        run_as_admin(script_path)
