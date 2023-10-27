# NetScan
A lightweight Network scanner which lists IPs and MAC Addresses of devices on a specified network.

![image](https://github.com/babylard/NetScan/assets/75695872/f3945ded-2162-42b9-8199-e3f3b8819123)


To begin, input the IP of the router you would like to scan for connected devices (You must be connected to the network) And Input the Range. Both fields will be properly set by default as of 0.0.3.
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
