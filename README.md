# NetScan
A lightweight Network scanner which lists IPs and MAC Addresses of devices on a specified network.

![image](https://github.com/babylard/NetScan/assets/75695872/202329ba-96cd-4c06-8f1b-ef160d3378b2)

# Dependencies
You may require WinPcap, Npcap, or other Packet Capturing software for the program to work properly. I highly reccomend Npcap over WinPcap, as WinPcap has ceased development a very long time ago. But if you are unable to get it to work with Npcap, WinPcap will work just fine.

I have also found that sometimes results wont display when using WinPcap, but it seems to work ok after retrying a few times for some reason.

For more information on vunrebilities of using WinPcap you can visit their website. 
If you're using macOS, then NetScan may work just fine out of the box as is. But if not I reccomend using Nmap.

If you are using a .py file alone rather than a .exe from the releases, be sure to run `pip install -r requirements.txt` to install all needed modules to function.

# Packet Capturing software Downloads
Npcap: https://npcap.com/#download

WinPcap: https://www.winpcap.org/install/default.htm

Nmap: https://nmap.org/download.html


# Usage
To begin, input the IP of the router you would like to scan for connected devices (You must be connected to the network, of course.) Along with the range. 

![python_lZQGK8S0eq](https://github.com/babylard/NetScan/assets/75695872/903b6d31-08b4-44e5-afcf-d8c5cc97d00e)

Both fields will be properly set by default as of 0.0.3, then press "Scan".
The program may freeze for a brief moment, as it is retrieving many details from devices. Afterwards you should have a neat looking list of IP's, MAC Addresses, OS information, etc.

