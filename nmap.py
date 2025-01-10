import tkinter as tk
from tkinter import messagebox
from scapy.all import sr1, IP, ICMP, TCP
import threading
import ipaddress
import subprocess

# Global variable to store scan results
scan_results = []

def start_scan():
    network = entry_network.get()
    scan_type = scan_option.get()
    
    if not network:
        messagebox.showwarning("Input Error", "Please enter a network range.")
        return

    try:
        ipaddress.ip_network(network)
    except ValueError:
        messagebox.showwarning("Input Error", "Invalid network range.")
        return

    # Clear previous results
    global scan_results
    scan_results = []
    results_text.delete(1.0, tk.END)
    results_text.insert(tk.END, "Scanning...\n")
    scan_thread = threading.Thread(target=scan_network, args=(network, scan_type))
    scan_thread.start()

def log_message(message):
    global scan_results
    scan_results.append(message)  # Store message for later use
    results_text.insert(tk.END, f"{message}\n")
    results_text.yview(tk.END)  # Scroll to the end of the text widget

def scan_network(network, scan_type):
    log_message(f"Debug: Starting scan for network {network}")
    network = ipaddress.ip_network(network, strict=False)
    log_message(f"Scanning network: {network}")

    for ip in network.hosts():
        address = str(ip)
        log_message(f"Debug: Scanning IP {address}")

        if scan_type in ["Ping", "All"]:
            perform_ping_scan(address)
        
        if scan_type in ["Port", "All"]:
            perform_port_scan(address)
        
        if scan_type in ["Aggressive", "All"]:
            perform_aggressive_scan(address)

    log_message("Scan complete!")
    show_ending_screen()

def perform_ping_scan(address):
    log_message(f"Performing Ping scan on {address}")
    packet = IP(dst=address)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        log_message(f"Host {address} is up")
    else:
        log_message(f"No response from {address}")

def perform_port_scan(address):
    log_message(f"Performing Port scan on {address}")
    open_ports = []
    for port in range(1, 1025):  # Scan ports 1 to 1024
        packet = IP(dst=address)/TCP(dport=port, flags='S')
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 18:
            open_ports.append(port)
    
    if open_ports:
        log_message(f"Open ports on {address}: {', '.join(map(str, open_ports))}")
    else:
        log_message(f"No open ports found on {address}")

def perform_aggressive_scan(address):
    log_message(f"Performing Aggressive scan on {address}")
    try:
        nmap_command = f"nmap -A {address}"
        result = subprocess.run(nmap_command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            log_message("Aggressive scan results:")
            log_message(result.stdout)
        else:
            log_message(f"Error during aggressive scan: {result.stderr}")
    except Exception as e:
        log_message(f"Exception during aggressive scan: {e}")

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()

def switch_to_scanner():
    welcome_frame.pack_forget()
    scanner_frame.pack(pady=20, expand=True, fill='both')

def show_ending_screen():
    scanner_frame.pack_forget()
    ending_frame.pack(pady=20, expand=True, fill='both')

def show_results():
    ending_frame.pack_forget()
    results_text_display.delete(1.0, tk.END)
    results_text_display.insert(tk.END, "\n".join(scan_results))
    results_frame.pack(pady=20, expand=True, fill='both')

def scan_again():
    results_frame.pack_forget()
    scanner_frame.pack(pady=20, expand=True, fill='both')

# Create the main window
root = tk.Tk()
root.title("Network Mapper")
root.geometry("1200x800")  # Set the window size

# Welcome Page
welcome_frame = tk.Frame(root)
welcome_frame.pack(pady=20, expand=True, fill='both')

welcome_label = tk.Label(welcome_frame, text="Welcome to the Network Mapper", font=("Helvetica", 24, "bold"))
welcome_label.pack(pady=20)

start_button = tk.Button(welcome_frame, text="Start", font=("Helvetica", 16), command=switch_to_scanner)
start_button.pack(pady=10)

# Main Scanner Page
scanner_frame = tk.Frame(root)
entry_network_label = tk.Label(scanner_frame, text="Enter the network (e.g., 10.0.2.0/24):", font=("Helvetica", 14))
entry_network_label.pack(pady=5)
entry_network = tk.Entry(scanner_frame, font=("Helvetica", 14))
entry_network.pack(pady=5)

scan_option = tk.StringVar(value="Ping")
tk.Label(scanner_frame, text="Select Scan Type:", font=("Helvetica", 14)).pack(pady=5)
tk.Radiobutton(scanner_frame, text="Ping Scan", variable=scan_option, value="Ping", font=("Helvetica", 14)).pack()
tk.Radiobutton(scanner_frame, text="Port Scan", variable=scan_option, value="Port", font=("Helvetica", 14)).pack()
tk.Radiobutton(scanner_frame, text="Aggressive Scan", variable=scan_option, value="Aggressive", font=("Helvetica", 14)).pack()
tk.Radiobutton(scanner_frame, text="All Scans", variable=scan_option, value="All", font=("Helvetica", 14)).pack()

scan_button = tk.Button(scanner_frame, text="Scan", font=("Helvetica", 16), command=start_scan)
scan_button.pack(pady=10)

results_text = tk.Text(scanner_frame, height=30, width=120, wrap=tk.WORD, font=("Helvetica", 14))  # Increase size and enable word wrap
results_text.pack(pady=10, expand=True, fill='both')

# Ending Screen
ending_frame = tk.Frame(root)
ending_label_1 = tk.Label(ending_frame, text="Thank you for using the Network Mapper!", font=("Helvetica", 24, "bold"))
ending_label_1.pack(pady=10)
ending_label_2 = tk.Label(ending_frame, text="I hope you had a great experience.", font=("Helvetica", 24, "bold"))
ending_label_2.pack(pady=10)

show_results_button = tk.Button(ending_frame, text="Show Results", font=("Helvetica", 16), command=show_results)
show_results_button.pack(pady=10)

quit_button = tk.Button(ending_frame, text="Quit", font=("Helvetica", 16), command=on_closing)
quit_button.pack(pady=10)

# Results Screen
results_frame = tk.Frame(root)
results_label = tk.Label(results_frame, text="Scan Results", font=("Helvetica", 24, "bold"))
results_label.pack(pady=20)

results_text_display = tk.Text(results_frame, height=30, width=120, wrap=tk.WORD, font=("Helvetica", 14))  # Increase size and enable word wrap
results_text_display.pack(pady=10, expand=True, fill='both')

scan_again_button = tk.Button(results_frame, text="Scan Again", font=("Helvetica", 16), command=scan_again)
scan_again_button.pack(pady=10)

quit_results_button = tk.Button(results_frame, text="Quit", font=("Helvetica", 16), command=on_closing)
quit_results_button.pack(pady=10)

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
