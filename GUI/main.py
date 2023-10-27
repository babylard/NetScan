import PySimpleGUI as sg
from scapy.all import *
import scapy.all as scapy
from manuf import manuf
import re

hostname = conf.route.route("0.0.0.0")[2]
show_short_oui = True

def get_device_type(mac_address):
    global show_short_oui
    p = manuf.MacParser()
    if show_short_oui:
        manufacturer = p.get_manuf(mac_address)
    else:
        manufacturer = p.get_manuf_long(mac_address)
    return manufacturer or "Unknown"


def scan(ip):
    print("Sending ARP requests...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if show_short_oui == True:
        print("\nIP\t\tMAC Address\t\tManufacturer\t\tOS\n----------------------------------------------------------------------------------------------------------------------------------------")
    else:
        print("\nIP\t\tMAC Address\t\tManufacturer\t\t\t\tOS\n----------------------------------------------------------------------------------------------------------------------------------------")
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        device_type = get_device_type(mac)
        try:
            syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=80, flags="S")
            response = scapy.sr1(syn_packet, timeout=1, verbose=False)
            if response:
                if response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
                    os_info = "Linux/Unix"
                elif response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x14:
                    os_info = "Windows"
                else:
                    os_info = "Unknown"
            else:
                os_info = "Unknown"
        except:
            os_info = "Error"
        if show_short_oui == True:
            print(f"{ip}\t\t{mac}\t\t{device_type}\t\t{os_info}\t\t")
        else:
            print(f"{ip}\t\t{mac}\t\t{device_type}\t\t\t\t{os_info}\t\t")
    print("\nDone\n----------------------------------------------------------------------------------------------------------------------------------------")


def is_valid_mac(mac_address):
    # Regular expression to validate MAC address format
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(mac_pattern, mac_address) is not None

sg.theme('Topanga') 

def help():
    layout2 = [
        [sg.Text('Known issues:')],
        [sg.Text('    1. No results? I could be wrong but I believe this is occurs when WinPcap is used. This is not an issue with NetScan, but rather WinPcap.')],
        [sg.Text('       This can also occur because the IP Range you entered was Invalid. 24 is set by default which should work just fine.')],
        [sg.Text('       For more information please view the README.MD in the Repository')],
        [sg.Text('')],
        [sg.Text("    2. OUI Manufacturer information is only 8 characters long. This issue has been resolved as of 0.0.4, however I thought this would also")],
        [sg.Text("       make a good feature. So there is now a checkbox located at the top to show Short OUIs, or long OUIs.")],
        [sg.Text('')],
        [sg.Text('Please report any bugs or issues you may find to williamchiozza@protonmail.com')]
    ]

    help_window = sg.Window('NetScan Help', layout2, resizable=True)

    while True:
        event, values = help_window.Read()
        if event in (None, "Exit"):
            break
    help_window.Close()


def main():
    global show_short_oui  # Declare the global variable in the main function
    layout = [  
        [sg.Text('Router IP'), sg.Text("                     IP Range"), sg.Checkbox("Short OUIs", key='OUI', default=True)],
        [sg.Input(hostname, key='_IN_', size=(20,1)), sg.Input("24", key="-IN-", size=(10,1))],
        [sg.Output(size=(85,25), key="-OUT-")],
        [sg.Button('Scan'), sg.Button('Exit'), sg.Button('Help')]
    ]

    window = sg.Window('NetScan', layout)

    while True:
        event, values = window.Read()
        if event in (None, 'Exit'):
            break
        if event in (None, 'Help'):
            help()
        elif event == 'Scan':
            show_short_oui = values['OUI']
            scan(ip=values['_IN_'] + "/" + values['-IN-'])

    window.Close()

main()