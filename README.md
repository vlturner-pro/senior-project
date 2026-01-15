# senior-project
A Python-based packet sniffer that utilizes Scapy and local port monitoring. Captures and analyzes live network traffic, unpacking and displaying network and transport layer header information to support network monitoring and SOC analysis.

** IMPORTANT- READ BEFORE USING! **
To use this app, run the file ui.py (NOTE: admin privileges required!). This is the main file.

** Skills Demonstrated **
- Network traffic capture and analysis
- IP, TCP, UDP, and ICMP header inspection
- Port-level traffic monitoring

** INSTRUCTIONS **

-- Capturing Traffic Basics --
On the main screen, click Run to begin the capture. Click Stop to end the capture. The Clear List button wipes the list of packets from the screen (but not from memory).
 
-- Filtering Captured Traffic --
Filter captured traffic by entering the source and destination IP in the two text boxes next to the stop button. To quickly enter the IP, highlight, then right-click a packet and click "Filter Src/Dst" in the popup. Toggle the direction by clicking the arrow icon between the address boxes. Click the Filter button to apply the filter. To show all captured traffic again, clear the text boxes for the addresses and click Filter.

-- Viewing Packet Details --
Highlight, then right click a packet and select "Packet Details" to view its information in detail.

-- Sender/Receiver Stats --
The Stats button displays all sender/receiver stats in the Runtime Stats window. Alternatively, you can click Src IP Stats or Dst IP Stats in the right-click menu of a packet to view stats on sent/received traffic from the source or destination of the selected packet.

-- Settings --
You can select an interface to gather traffic from using the dropdown interface menu. Local interfaces indicate port monitoring, while others are interfaces utilizing Scapy to scan the network.

In Run Settings, you can enter an amount of time to run the program for, or a sample size of packets to take. The sniffer will automatically stop once these limits have been reached.

The Reset Data button is used to clear all packets from memory.

The Apply button applies current interface and run settings.
