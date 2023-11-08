import scapy.all as scapy
import manuf
import datetime


router = input("Input IP of the router you would like to scan: ")
range = input("Range (24 is reccomended): ")
done = False
now = datetime.datetime.now()

def get_device_type(mac_address):
    p = manuf.MacParser()
    manufacturer = p.get_manuf_long(mac_address)
    return manufacturer or "Unknown"

def scan(ip):
    print("Sending ARP requests...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    

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
                elif response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x18:
                    os_info = "Mac OS"
                elif "Android" in response.summary():
                    os_info = "Android"
                elif "iOS" in response.summary():
                    os_info = "iOS"
                else:
                    os_info = "Unknown"
            else:
                os_info = "Unknown"
        except:
            os_info = "Error"
        print(f"{ip}\t\t{mac}\t\t{device_type}\t\t\t\t{os_info}\t\t")
    print("\nDone\n----------------------------------------------------------------------------------------------------------------------------------------")
    print("Finished at " + str(now))

scan(router + "/" + range)
input("Press Enter to exit...")