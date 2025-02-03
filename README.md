# NetScan
A Network scanner that lists IPs, MAC Addresses, and other information about devices on a network, which can also Deuath devices.

![image](https://github.com/babylard/NetScan/assets/75695872/40ad710c-4471-4910-91e3-2e29567890dc)

# Dependencies
You'll probably need WinPcap, Npcap, or other Packet Capturing software for the program to work properly.

Be sure to run `pip install -r requirements.txt`

# Packet Capturing software Downloads

1.    [NpCap](https://npcap.com/#download)
2.    [WinPcap](https://www.winpcap.org/install/default.htm)
3.    [Nmap](https://nmap.org/download.html)

Please note that you are only required to have one of these, or other software with the same functionality.

# Usage
To begin, input the IP of the router you would like to scan for connected devices (You must be connected to the network, of course.) Along with the range. 
Both fields will be properly set by default as of 0.0.3, then press "Scan".
The output will begin listing devices it finds in realtime, and should let you know when it is done. Afterwards you should have a neat looking list of IP's, MAC Addresses, OS information, etc.

Please view the [Documentation](https://github.com/babylard/NetScan/blob/main/Documentation/docs.ipynb) for more in depth information.
