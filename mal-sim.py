import socket
import winreg
import time

def simulate_network_connection(ip, port):
    """Simulate a network connection to a specified IP address and port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        print(f"Successfully connected to {ip}:{port}")
        return sock
    except Exception as e:
        print(f"Failed to connect to {ip}:{port} - {e}")
        return None

def create_registry_key(key, sub_key, value_name, value):
    """Create a registry key and set a value."""
    try:
        with winreg.CreateKey(key, sub_key) as reg_key:
            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_SZ, value)
            print(f"Registry key {sub_key} created with value {value_name}={value}")
    except Exception as e:
        print(f"Failed to create registry key {sub_key} - {e}")

if __name__ == "__main__":
    ip_address = "93.184.216.34"  # Example IP address (example.com)
    port = 80

    # Simulate network connection and keep it open
    sock = simulate_network_connection(ip_address, port)

    # Simulate registry key changes
    registry_key = winreg.HKEY_CURRENT_USER
    sub_key = "Software\\MalTrackTest"
    value_name = "TestValue"
    value = "TestData"

    create_registry_key(registry_key, sub_key, value_name, value)

    print("Malware simulation complete. Registry key created and network connection made.")

    # Keep the connection open indefinitely
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if sock:
            sock.close()
        print("Program terminated. Connection closed.")
