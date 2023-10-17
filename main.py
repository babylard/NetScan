import scapy.all as scapy
import datetime
import itertools
import threading
import time
import sys
import os



router = input("Input IP of the router you would like to scan: ")
done = False

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rSending ARP requests (Takes longer with many devices on network)   ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\n\rDone     ')

t = threading.Thread(target=animate)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("\nIP\t\t\tMAC Address\n------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

t.start()
scan(router + "/24")
done = True

input("")