# NetScan
A lightweight Network scanner which lists IPs and MAC Addresses of devices on a specified network.

![image](https://github.com/babylard/NetScan/assets/75695872/1b2373ae-0785-4666-9eca-9946bbb422a6)

# Dependencies
You may require WinPcap, Npcap, or other Packet Capturing software for the program to work properly. I highly reccomend Npcap over WinPcap, as WinPcap has ceased development a very long time ago. But if you dont care for security, WinPcap will work just fine.

If you are using a .py file alone rather than a .exe from the releases, be sure to run `pip install -r requirements.txt` to install all needed modules to function.

# Packet Capturing software Downloads

1.    [NpCap](https://npcap.com/#download)
2.    [WinPcap](https://www.winpcap.org/install/default.htm)
3.    [Nmap](https://nmap.org/download.html)

Please note that you are only required to have one of these, or other software with the same functionality.

# Usage
To begin, input the IP of the router you would like to scan for connected devices (You must be connected to the network, of course.) Along with the range. 

![python_G0p6xfFfVJ](https://github.com/babylard/NetScan/assets/75695872/f3169405-0b50-4607-b1c8-f3ec8d7c303b)

Both fields will be properly set by default as of 0.0.3, then press "Scan".
The program may freeze for a brief moment, as it is retrieving many details from devices. Afterwards you should have a neat looking list of IP's, MAC Addresses, OS information, etc.



Please view the [Documentation](https://github.com/babylard/NetScan/blob/main/Documentation/docs.ipynb) for more in depth information.
