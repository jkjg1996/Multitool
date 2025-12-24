
def port_scanner():
    import socket
    target = input("Enter the IP address to scan: ").strip()
    if not target:
        print("No target entered.")
        return
    ports_input = input("Enter ports to scan (comma-separated, or leave blank for common ports): ").strip()
    if ports_input:
        ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]   

        
    common_services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
        110: 'pop3', 139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
        3389: 'rdp', 8080: 'http-proxy'
    }

    print(f"Scanning {target} on ports: {ports}")
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.6)
            try:
                result = s.connect_ex((target, port))
            except Exception as e:
                print(f"Error scanning {target}:{port} -> {e}")
                continue
            # determine service name if possible
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = common_services.get(port, 'unknown')

            if result == 0:
                print(f"Port {port} ({service}) is OPEN")
            else:
                print(f"Port {port} ({service}) is CLOSED")





import platform
import subprocess
import os

def show_system_info():
    try:
        sys_val = platform.system()
        rel_val = platform.release()
        proc_val = platform.processor()
        print(f"System: {sys_val}")
        print(f"Release: {rel_val}")
        print(f"Processor: {proc_val}")
    except Exception as e:
        print("Error in show_system_info:", e)

def list_files():
    path = input(" Enter folder path(or leave empty for current folder):").strip()
    if path == "":
        path = "."
    try:
        files = os.listdir(path)
        print(f"\nFiles in {os.path.abspath(path)}:")
        for f in files:
            print("  ", f)
    except Exception as e:
        print("Error :( ", e)

def ping_website():
    site = input(" Enter website for pinging:").strip()
    if site:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.call(["ping", param, "4", site])
    else:
        print("No website entered.")

def ping_sweep():
    print("Starting ping sweep...")
    base_ip = input("Enter the base IP (e.g., 192.168.1): ").strip()
    if not base_ip:
        print("No base IP entered.")
        return
    param = "-n" if platform.system().lower() == "windows" else "-c"
    print(f"Pinging {base_ip}.1 to {base_ip}.254...")
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            result = subprocess.run(["ping", param, "1", ip], stdout=subprocess.DEVNULL)
            if result.returncode == 0:
                print(f"Host {ip} is UP")
            else:
                print(f"Host {ip} is DOWN (return code: {result.returncode})")
        except Exception as e:
            print(f"Error pinging {ip}: {e}")

def crack_password_hash():
    import hashlib
    hash_to_crack = input("Enter the hash to crack: ").strip()
    wordlist_path = input("Enter path to wordlist file: ").strip()
    hash_type = input("Enter hash type (md5/sha1/sha256): ").strip().lower()
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                if hash_type == 'md5':
                    hashed = hashlib.md5(word.encode()).hexdigest()
                elif hash_type == 'sha1':
                    hashed = hashlib.sha1(word.encode()).hexdigest()
                elif hash_type == 'sha256':
                    hashed = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print("Unsupported hash type.")
                    return
                if hashed == hash_to_crack:
                    print(f"Password found: {word}")
                    return
        print("Password not found in wordlist.")
    except Exception as e:
        print("Error:", e)

def banner_grabber():
    import socket
    target = input("Enter the IP address: ").strip()
    port = input("Enter the port to grab banner from: ").strip()
    if not port.isdigit():
        print("Invalid port number.")
        return
    port = int(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            s.sendall(b"\\r\\n")
            banner = s.recv(1024)
            print(f"Banner from {target}:{port} -> {banner.decode(errors='ignore')}")
    except Exception as e:
        print(f"Could not grab banner: {e}")

def main_menu():
    while True:
        print("\n=== Ethical Hacking Multi-Tool ===")
        print("1. Show System Info")
        print("2. List Files in Folder")
        print("3. Ping a Website")
        print("4. Network Ping Sweep")
        print("5. Crack a Password Hash")
        print("6. Port Scanner")
        print("7. Baner Grabbing")
        print("8. Exit")
        choice = input("Choose an option: ").strip()
        if choice == '1':
            show_system_info()
        elif choice == '2':
            list_files()
        elif choice == '3':
            ping_website()
        elif choice == '4':
            ping_sweep()
        elif choice == '5':
            crack_password_hash()
        elif choice == '6':
            port_scanner()
        elif choice == '7':
            banner_grabber()
        elif choice == '8':
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main_menu()

