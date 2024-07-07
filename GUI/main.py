import customtkinter as ctk
from tkinter import *
from tkinter import filedialog
from scapy.all import *
import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from manuf import manuf
import datetime
import socket
import threading
import sys
import webbrowser
import json
import os

# Variables
hostname = conf.route.route("0.0.0.0")[2]
show_short_oui = True
now = datetime.datetime.now()
stop_deauth_event = threading.Event()
deauth_thread = None

# Class to redirect stdout to Tkinter text widget
class TextRedirector:
    def __init__(self, widget):
        self.widget = widget

    def write(self, text):
        self.widget.insert(ctk.END, text)
        self.widget.see(ctk.END)

    def flush(self):
        pass

# Network functions
def deauth_function(target_mac, bssid, count=1):
    try:
        global stop_deauth_event

        stop_deauth_event.clear()  # Clears the event flag

        while not stop_deauth_event.is_set():
            deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
            for _ in range(count):
                scapy.send(deauth_packet, verbose=False)
            
            time.sleep(10)
    except:
        print("Invalid input.")

def portscan_function(ip):
    for port in range(65535):
        try:
            serv = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            serv.bind((ip,port))       
        except:
            print('\033[1;32;40m [OPEN]: ', port)
    
        serv.close() #close connection

def start_deauth(target_mac, bssid, count=1):
    global deauth_thread

    # Checks if there is an existing deauth thread, and if yes, stops it before starting a new one
    if deauth_thread and deauth_thread.is_alive():
        stop_deauth_thread()

    deauth_thread = threading.Thread(target=deauth_function, args=(target_mac, bssid, count))
    deauth_thread.start()

def stop_deauth_thread():
    global stop_deauth_event
    stop_deauth_event.set()
    print("Stopped Deauth.")

def start_portscan(ip):
    global portscan_thread

    if portscan_thread and portscan_thread.is_alive():
        stop_portscan_thread()
    
    portscan_thread = threading.Thread(target=portscan_function, args=(ip))
    portscan_thread.start()

def get_device_type(mac_address):
    global show_short_oui
    p = manuf.MacParser()
    if show_short_oui:
        manufacturer = p.get_manuf(mac_address)
    else:
        manufacturer = p.get_manuf_long(mac_address)
    return manufacturer or "Unknown"

def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror as e:
        return "Unknown"

def scan(ip):
    print("Sending ARP requests...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if show_short_oui:
        print("\nIP\t\tMAC Address\t\tManufacturer\t\tOS\t\tHostname\n---------------------------------------------------------------------------------------------------------------------------------")
    else:
        print("\nIP\t\tMAC Address\t\tManufacturer\t\t\t\tOS\t\tHostname\n-----------------------------------------------------------------------------------------------------------------------------------------------------------")
    
    for answered_packet in answered_list:
        ip = answered_packet[1].psrc
        mac = answered_packet[1].hwsrc
        device_type = get_device_type(mac)
        os_info = "Unknown"

        try:
            syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=False)

            if response:
                if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
                    os_info = "Linux/Unix"
                elif response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x14:
                    os_info = "Windows"
                elif response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x18:
                    os_info = "Mac OS"
                elif "Android" in response.summary():
                    os_info = "Android"
                elif "iOS" in response.summary():
                    os_info = "iOS"
        except:
            os_info = "Error"

        host_name = get_hostname(ip)

        if show_short_oui:
            print(f"{ip}\t\t{mac}\t\t{device_type}\t\t{os_info}\t\t{host_name}")
        else:
            print(f"{ip}\t\t{mac}\t\t{device_type}\t\t\t\t{os_info}\t\t{host_name}")

    print("\nDone\n------------------------------------------------------------------------------------------------------------------------")
    print("Finished at " + str(now))

def scan_thread(ip):
    scanning_thread = threading.Thread(target=scan, args=(ip,))
    scanning_thread.start()

# GUI
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("green")

def docs():
    webbrowser.open_new_tab("https://github.com/babylard/NetScan/blob/main/Documentation/docs.ipynb")

def deauth_window():
    def on_deauth():
        target_mac = target_entry.get()
        router_mac = router_entry.get()
        if target_mac and router_mac:
            start_deauth(target_mac=target_mac, bssid=router_mac)
            deauth_output.insert(ctk.END, f"Deauth loop started.\n--------------------------------------------------------------------\n")
        else:
            deauth_output.insert(ctk.END, "Values not set. Please enter details in both Target MAC and Router MAC. If you need any help, feel free to read the documentation.\n")
    
    def on_stop_deauth():
        deauth_output.insert(ctk.END, "Stopped Deauth.\n")
        stop_deauth_thread()

    deauth_win = ctk.CTkToplevel(root)
    deauth_win.title("Deauth Window")
    
    ctk.CTkLabel(deauth_win, text="Target MAC:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ctk.CTkLabel(deauth_win, text="Router MAC:").grid(row=0, column=1, padx=5, pady=5, sticky="w")
    
    target_entry = ctk.CTkEntry(deauth_win)
    router_entry = ctk.CTkEntry(deauth_win)
    target_entry.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    router_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    
    deauth_output = ctk.CTkTextbox(deauth_win, width=450, height=300)
    deauth_output.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")
    
    ctk.CTkButton(deauth_win, text="Deauth", command=on_deauth).grid(row=3, column=0, padx=5, pady=5, sticky="w")
    ctk.CTkButton(deauth_win, text="Stop Deauth", command=on_stop_deauth).grid(row=3, column=1, padx=5, pady=5, sticky="w")

def validate_numeric_input(value):
    return all(char.isdigit() or char == "." for char in value) or value == ""

def main_window():
    global root, output_text, ip_entry, range_entry
    root = ctk.CTk()
    root.title("NetScan")
    root.geometry("753x558")

    validate_command = root.register(validate_numeric_input)

    def on_scan_network():
        global show_short_oui
        show_short_oui = oui_var.get()
        ip = ip_entry.get() + "/" + range_entry.get()
        scan_thread(ip)

    def on_clear_output():
        output_text.delete(1.0, ctk.END)
    
    def donothing():
        print("Unimplemented")

    def save():
        # Open a file dialog to choose the save location
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            # Sanitize file name by removing invalid characters
            file_name = os.path.basename(file_path)
            sanitized_file_name = "".join(c for c in file_name if c.isalnum() or c in "_-.")
            
            # Add "NetScan_" to the beginning of the file name
            if not sanitized_file_name.endswith(".json"):
                sanitized_file_name += ".json"
            if not sanitized_file_name.startswith("NetScan_"):
                sanitized_file_name = "NetScan_" + sanitized_file_name
            
            # Construct full file path with sanitized file name
            save_file_path = os.path.join(os.path.dirname(file_path), sanitized_file_name)
            
            # Save the current state to a JSON file
            data = {
                "router_ip": ip_entry.get(),
                "ip_range": range_entry.get(),
                "output": output_text.get(1.0, ctk.END),
                "short_oui": oui_var.get()
            }
            with open(save_file_path, 'w') as file:
                json.dump(data, file, indent=4)
            print(f"File saved to {save_file_path}")

    def open_file():
        # Open a file dialog to choose the file to open
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            # Check if the file is valid for your program
            if not file_path.endswith(".json") or not os.path.basename(file_path).startswith("NetScan_"):
                print(f"Invalid file selected: {file_path}")
                return
            
            # Load the state from the JSON file
            with open(file_path, 'r') as file:
                data = json.load(file)
                ip_entry.delete(0, ctk.END)
                ip_entry.insert(0, data["router_ip"])
                range_entry.delete(0, ctk.END)
                range_entry.insert(0, data["ip_range"])
                output_text.delete(1.0, ctk.END)
                output_text.insert(ctk.END, data["output"])
                oui_var.set(data.get("short_oui", False))
            print(f"File loaded from {file_path}")

    ctk.CTkLabel(root, text="Router IP").grid(row=0, column=0, padx=1, pady=1, sticky="w")
    ctk.CTkLabel(root, text="IP Range").grid(row=0, column=1, padx=1, pady=1, sticky="w")

    ip_entry = ctk.CTkEntry(root, width=120)
    ip_entry.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ip_entry.insert(0, hostname)
    ip_entry.configure(validate="key", validatecommand=(validate_command, "%P"))

    range_entry = ctk.CTkEntry(root, width=40)
    range_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    range_entry.insert(0, "24")
    range_entry.configure(validate="key", validatecommand=(validate_command, "%P"))

    oui_var = ctk.BooleanVar()
    oui_check = ctk.CTkCheckBox(root, text="Short OUIs", variable=oui_var)
    oui_check.grid(row=0, column=2, padx=1, pady=1, sticky="w")

    output_text = ctk.CTkTextbox(root, width=750, height=450)
    output_text.grid(row=2, column=0, columnspan=3, padx=1, pady=1, sticky="w")

    sys.stdout = TextRedirector(output_text)

    ctk.CTkButton(root, text="Scan Network", command=on_scan_network).grid(row=3, column=0, padx=5, pady=5, sticky="w")

    def newfile():
        on_clear_output()
        range_entry.delete(0, ctk.END)
        range_entry.insert(0, "24")
        ip_entry.delete(0, ctk.END)
        ip_entry.insert(0, hostname)
        oui_var.set(False)

    menubar = Menu(root)
    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="New", command=newfile)
    filemenu.add_command(label="Open", command=open_file)
    filemenu.add_command(label="Save", command=save)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    helpmenu = Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Documentation", command=docs)
    menubar.add_cascade(label="Help", menu=helpmenu)

    viewmenu = Menu(menubar, tearoff=0)
    viewmenu.add_command(label="Clear", command=on_clear_output)
    viewmenu.add_command(label="Deauth", command=deauth_window)
    viewmenu.add_command(label="Port scan", command=donothing)
    menubar.add_cascade(label="View", menu=viewmenu)

    root.config(menu=menubar)
    root.mainloop()

if __name__ == "__main__":
    main_window()