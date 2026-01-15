# Research nslookup (python)
# Add timer/number + stats
# Binding port - your pc, sniff- anything directed at ip
# Sniffing is easy on a hub, difficult on switch

# Scapy
from scapy.all import *
import scapy.interfaces
import scapy_packet_formatter as spf
import packet_formatter as pf

# Messaging system
import threading
import queue

_messages = {}
_mesLock = threading.Lock()

import socket
import textwrap
import time

import psutil

def get_active_interfaces():
    # Get network interfaces and their addresses
    interfaces = psutil.net_if_addrs()
    # Get network interface statuses
    interface_statuses = psutil.net_if_stats()

    active_interfaces = {}

    for interface, addr_info in interfaces.items():
        # Check if the interface is up and running
        if interface_statuses[interface].isup:
            for addr in addr_info:
                # We're interested in IPv4 addresses
                if addr.family == socket.AF_INET:
                    #active_interfaces[interface] = addr.address
                    active_interfaces[interface + " (Local)"] = addr.address
    #print(active_interfaces)
    return active_interfaces


# Gets the user's IP currently in use
# Test all local interfaces for the one that receives the most packets
def get_active_ip():
    # Get the list of active interfaces and their IPs
    active_interfaces = get_active_interfaces()
    print("ACTIVE INTERFACES")
    print(active_interfaces)

    if active_interfaces:
        # Highest number of packets received in 2s
        packetRecord = 0
        # Most active IP
        mostActiveIP = None

        # Name of the most active IP interface
        mostActiveInterface = None

        # Timer for tests
        timeLimit = 2

        print("Network interfaces found, testing for active ip:")
        # Print active interfaces, test each for incoming packets
        for interface, ip in active_interfaces.items():
            print(f"Interface: {interface}, IP Address: {ip}")

            # Initialize mostActiveIP with first IP
            if mostActiveIP is None:
                mostActiveIP = ip
                mostActiveInterface = interface

            # Count the number of packets received
            packetCount = 0
            # Count the time elapsed for test
            timer = 0

            # Create raw socket for sniffing
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((ip, 0))
            # Include IP headers in packet capture
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # If on Windows, turn on promiscuous mode to capture all packets
            if hasattr(socket, 'SIO_RCVALL'):
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            # Set 2 second timeout to prevent indefinite blocking
            conn.settimeout(2)

            try:
                start = time.time()
                end = start
                while True:
                    try:
                        # If time is up, compare number of packets collected to record. Update active IP if greater
                        timer += (end - start)
                        print("Time elapsed: {}".format(timer))
                        if timer >= timeLimit:
                            print("Packets received from {}: {}".format(ip, packetCount))
                            if packetCount > packetRecord:
                                # Only pick a Wi-Fi or Ethernet interface (to avoid interfaces solely with internal processes)
                                if "Wi-Fi" in interface or "Ethernet" in interface:
                                    packetRecord = packetCount
                                    mostActiveIP = ip
                                    mostActiveInterface = interface
                            break
                        conn.recvfrom(65535)
                        end = time.time()
                        print("Packet received!")
                        packetCount += 1
                    except socket.timeout:
                        end = time.time()
                        print("No packet received, continuing")
                        continue

            finally:
                # Turn off promiscuous mode (for Windows)
                if hasattr(socket, 'SIO_RCVALL'):
                    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                conn.close()

        # Return the active IP (the one with the most traffic during the test)
        print("Active Interface: {}".format(mostActiveInterface))
        print("Active IP: {}".format(mostActiveIP))
        
        return (mostActiveInterface, mostActiveIP)
        
    else:
        print("No active network interfaces found.")
        return None


# Initialize global variables

# PERSISTENT VARIABLES

# Initialize settings
_settings = {}
_settings["time limit"] = None
_settings["packet limit"] = None
# Get local interfaces
_settings["interfaces"] = get_active_interfaces()
# Get network interfaces (From Scapy)
for iface in get_working_ifaces():
    # Instead of IP, keyword "Scapy" lets sniffer know this is a scapy interface
    # Scapy will use interface name rather than IP (the dict key rather than the value)
    _settings["interfaces"][iface.name] = "Scapy"


# Get the most active local interface to initialize to (default)
_settings["current interface"] = get_active_ip()

# The most active ip
_host = _settings["current interface"][1]


# Packet-related variables

# A list of received packets in order
_orderedPackets = []

# Tuple of sender and receiver IPs (For easier searching, each packet exists in both)
senderIPs = {}
receiverIPs = {}
_packets = [senderIPs, receiverIPs]

# Total time elapsed (across all runs) - resets after erasing data
_time_elapsed = 0


# RUN-SPECIFIC VARIABLES - reset with each new sniffing run
# Time when sniffing starts (temp value- gets updated at start of a run)
start_time = time.time()
# Packets gathered in current run
packets_this_run = 0


# Gets called by UI when start button clicked- sniffs using ports or Scapy, depending on settings
def main():
    global _settings
    global _host

    if _settings["current interface"] is not None:

        _host = _settings["current interface"][1]

        if _host == "Scapy":
            print("Sniffing network with Scapy...")
            sniffWithScapy()
        else:
            print("Sniffing locally using ports...")
            sniffWithPorts()

        print("Finished sniffing.")

    else:
        print("No interfaces detected. Stopping scan.")


# SNIFFER FUNCTIONS

# PORTS

# Sniffs traffic coming through PC ports (doesn't get all traffic in network)
def sniffWithPorts():
    # List of received packets in order
    global _orderedPackets
    global _packets
    global packets_this_run
    # Timer
    global _time_elapsed
    #global time_this_run
    # Host
    global _host
    # Change global variable _host to match settings
    _host = _settings["current interface"][1]

    # Temporary variables (for current start/stop run)- used for time/packet limits
    # Time elapsed this run
    time_this_run = 0
    # Packets captured this run
    packets_this_run = 0

    # Prints IP address
    print("My IP:")
    print(_host)

    #NOTE: try IPPROTO_RAW (IP packets) IPPROTO_IP is a dummy protocol?
    # Create raw socket for sniffing
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    conn.bind((_host, 0))

    print("SOCKET: " + str(conn.getsockname()))

    # Include IP headers in packet capture
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # If on Windows, turn on promiscuous mode to capture all packets
    if hasattr(socket, 'SIO_RCVALL'):
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Set 2 second timeout to prevent indefinite blocking
    conn.settimeout(2)

    try:
        while True:
            # Timer
            start = time.time()
            print("time this run: " + str(time_this_run))
            
            if _settings["time limit"] != None:
                if time_this_run >= _settings["time limit"]:
                    print("Time limit reached: " + str(time_this_run))
                    break
            
            if _settings["packet limit"] != None:
                if packets_this_run >= _settings["packet limit"]:
                    print("Max packets reached: " + str(packets_this_run))
                    break

            try:
                #print("start of loop")
                raw_data, addr = conn.recvfrom(65535)

                # Timer
                end = time.time()
                time_since_packet = end-start
                start = end
                # Total time passed over all runs (one run = clicking "Start" and then either clicking "Stop" or reaching time/packet limit)
                _time_elapsed += time_since_packet
                # Time passed since last clicking "Start"
                time_this_run += time_since_packet

                if processPacket(raw_data, _packets, ip=None, sender=1, receiver=1, store_pkt=1) == 1:
                    packets_this_run += 1
                    print("packets this run: " + str(packets_this_run))

            except socket.timeout:
                #print("No packet received, continuing")
                pass
            
            # CHECK FOR MESSAGES FROM UI

            # Message ui -> sniffer: control sniffing
            mes = GetMessage("sniffer")
            if mes is not None:
                #print("message: " + mes)
                
                # -1: Stop sniffing
                if mes == -1:
                    print("Stop message received")
                    break

            end = time.time()
            print("time increment: " + str(end-start))
            # Total time passed over all runs (one run = clicking "Start" and then either clicking "Stop" or reaching time/packet limit)
            _time_elapsed += (end-start)
            # Time passed since last clicking "Start"
            time_this_run += (end-start)

    finally:
        # Turn off promiscuous mode (for Windows)
        if hasattr(socket, 'SIO_RCVALL'):
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        conn.close()

    # Send "finished" message to let ui know to stop thread
    SendMessageLocal("ui", -1)
    print("exited loop")


# Takes raw packet and processes/filters it
# raw_data: the packet, ip (str): the ip address to filter by (user's ip by default), sender (bool): include packets addressed from ip
# receiver (bool): include packets addressed to ip, store_pkt (bool): store packet in list/dict,
# proto_type (for testing): filters out packets with a non-matching proto number (-1: all, 1: icmp, 6: tcp, 17: udp)
def processPacket(raw_data, packetList, ip=_settings["current interface"][1], sender=1, receiver=1, store_pkt=0, proto_type=-1):
    global _time_elapsed

    # Check IP version before unpacking
    ver = check_ip_ver(raw_data)
    # If IPv4
    if ver == 4:
        print("IPv4 packet")

        ver, header_length, dscp, ecn, total_len, identification, flags_r, flags_df, flags_mf, fragment_offset, ttl, proto, header_checksum, src, target, data = pf.ipv4_packet(raw_data)


        # Protocol filter (for testing purposes)- only store/print packets with proto number of argument
        if proto_type != -1 and proto_type != proto:
            print("PROTO DOESN'T MATCH FILTER")
            return 0



        # If sender filter is 1, include packet if addressed from ip. If receiver filter is 1, include packet if addressed to ip
        # If ip is None, examine the packet regardless of sender/receiver
        if ip == None or (sender == 1 and src == ip) or (receiver == 1 and target == ip):

            # Create dictionary entry for IP packet
            ipv4Entry = {}
            
            # Number of packet
            ipv4Entry["no"] = len(_orderedPackets)
            # Time packet was received
            ipv4Entry["time"] = round(_time_elapsed, 3)


            ipv4Entry["ver"] = ver
            ipv4Entry["header_length"] = header_length

            ipv4Entry["dscp"] = dscp
            ipv4Entry["ecn"] = ecn
            ipv4Entry["total_length"] = total_len
            ipv4Entry["identification"] = identification
            ipv4Entry["flags_r"] = flags_r
            ipv4Entry["flags_df"]= flags_df
            ipv4Entry["flags_mf"]= flags_mf
            ipv4Entry["fragment_offset"] = fragment_offset


            ipv4Entry["ttl"] = ttl
            ipv4Entry["proto"] = proto

            ipv4Entry["header_checksum"] = header_checksum


            ipv4Entry["src"] = src
            ipv4Entry["target"] = target
            # Contains raw data from payload
            ipv4Entry["data"] = data


            #print('Version: {}, Header Length: {}, TTL: {}, Protocol: {}'.format(ver, header_length, ttl, proto))
            # Prints source and dest IP address
            #print("Src: {}, Dest: {}".format(src, target))

            # If packet fits the filter, extract the transport layer packet
            # ICMP packet
            if proto == 1:
                icmp_type, icmp_code, icmp_checksum, icmp_data = pf.icmp_packet(data)
                # Create dictionary entry for icmp packet
                icmpEntry = {}
                icmpEntry["type"] = icmp_type
                icmpEntry["code"] = icmp_code
                icmpEntry["checksum"] = icmp_checksum
                icmpEntry["data"] = icmp_data

                # Contains payload of ip packet as a dictionary
                ipv4Entry["payload"] = icmpEntry
                
                print("ICMP packet:")
                #print('Type: {}'.format(icmp_type))
                #print("Data:")
                #print(icmp_data)

            # TCP packet
            elif proto == 6:                
                tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgement, tcp_offset, tcp_reserved, tcp_flag_cwr, tcp_flag_ece, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, tcp_window, tcp_checksum, tcp_urgent_pointer, tcp_data = pf.tcp_segment(data)
                
                # Create dictionary entry for tcp packet
                tcpEntry = {}
                tcpEntry["src_port"] = tcp_src_port
                tcpEntry["dest_port"] = tcp_dest_port
                tcpEntry["sequence"] = tcp_sequence
                tcpEntry["acknowledgement"] = tcp_acknowledgement
                
                tcpEntry["offset"] = tcp_offset
                tcpEntry["reserved"] = tcp_reserved
                tcpEntry["flag_cwr"] = tcp_flag_cwr
                tcpEntry["flag_ece"] = tcp_flag_ece


                tcpEntry["flag_urg"] = tcp_flag_urg
                tcpEntry["flag_ack"] = tcp_flag_ack
                tcpEntry["flag_psh"] = tcp_flag_psh
                tcpEntry["flag_rst"] = tcp_flag_rst
                tcpEntry["flag_syn"] = tcp_flag_syn
                tcpEntry["flag_fin"] = tcp_flag_fin

                tcpEntry["window"] = tcp_window
                tcpEntry["checksum"] = tcp_checksum
                tcpEntry["urgent_pointer"] = tcp_urgent_pointer
                

                tcpEntry["data"] = tcp_data

                # Contains payload of ip packet as a dictionary
                ipv4Entry["payload"] = tcpEntry
                
                print("TCP packet")
                #print('Src Port: {}, Dest Port: {}'.format(tcp_src_port, tcp_dest_port))
                
                
                #print("Data:")
                #print(tcp_data)

            # UDP packet
            elif proto == 17:
                udp_src_port, udp_dest_port, udp_size, udp_checksum, udp_data = pf.udp_segment(data)
                
                # Create dictionary entry for udp packet
                udpEntry = {}
                udpEntry["src_port"] = udp_src_port
                udpEntry["dest_port"] = udp_dest_port
                udpEntry["size"] = udp_size

                udpEntry["checksum"] = udp_checksum

                udpEntry["data"] = udp_data

                # Contains payload of ip packet as a dictionary
                ipv4Entry["payload"] = udpEntry
                
                print("UDP packet")
                #print('Src Port: {}, Dest Port: {}, Size: {}'.format(udp_src_port, udp_dest_port, udp_size))
                #print('Data:')
                #print(udp_data)

            # Other type of Transport Layer packet
            else:
                print("Unable to unpack Transport Layer packet")
                ipv4Entry["payload"] = "not unpacked"

            # If store command is 1, store in list/dict
            if store_pkt == 1:
                storePacket(ipv4Entry, packetList)

        # If packet does not match filter, do nothing
        else:
            return 0
        

    elif ver == 6:
        print("IPv6 packet")
        return 0
    else:
        print("Unrecognized network layer protocol")
        return 0


    # If the packet was stored, return 1 for success
    return 1


# Returns IP version from raw packet data (usually IPv4, but an IPv6 packet would cause errors)
def check_ip_ver(data):
    version_header_length = data[0]
    # Bitwise operation, bit shift 4 to the right
    version = version_header_length >> 4
    return version


# SCAPY

# Use Scapy's AsyncSniffer to get packets from network
def sniffWithScapy():
    global _settings
    global _orderedPackets
    global _packets
    global packets_this_run
    # Timer
    global _time_elapsed
    global start_time

    global _host
    # Change global variable _host to match settings
    _host = _settings["current interface"][1]
    #_host = _settings["current interface"][0]

    # Temporary variables (for current start/stop run)- used for time/packet limits
    # Packets captured this run
    packets_this_run = 0
    
    scapysniffer = AsyncSniffer(stop_filter = lambda pkt: isDone(), iface=_settings["current interface"][0], prn=scapyPacketCallback, store=0, timeout=None)
    
    # Timer
    start_time = time.time()
    
    scapysniffer.start()
    while True:
        print("Start of loop")

        # Join the scapy sniffer thread (set timeout to prevent indefinite blocking)
        scapysniffer.join(timeout=2)

        # Once timeout has been hit...

        # If isDone has been hit by scapy sniffer (packet received + conditions met), exit the loop
        if scapysniffer.running == False:
            print("Finished sniffing")
            break
        
        # If scapy sniffer is still looking for packets, check isDone
        # Sniffer will only check isDone itself if it gets a packet
        # The extra check prevents freezing when no packets received
        else:
            if isDone():
                print("Finished sniffing (timeout)")
                scapysniffer.stop()
                break
        
        print("End of loop")

    # When sniffing is finished, update total time elapsed
    _time_elapsed +=  time.time() - start_time

    # Send "finished" message to let ui know to stop thread
    SendMessageLocal("ui", -1)
    print("exited loop")


# Checks if any of the stop conditions for sniffing have been met
def isDone():
    global _settings
    global start_time
    global packets_this_run

    # Check for finished message from UI
    # Message ui -> sniffer: control sniffing
    mes = GetMessage("sniffer")
    if mes is not None:
        # -1: Stop sniffing
        if mes == -1:
            print("Stop message received")
            return True

    # Check if packet limit has been reached
    if _settings["packet limit"] != None:
        if packets_this_run >= _settings["packet limit"]:
            print("Packet limit reached")
            return True

    # Check if time limit has been reached
    if _settings["time limit"] != None:
        if (time.time() - start_time) >= _settings["time limit"]:
            print("Time limit reached")
            return True
    
    # Return False if not finished
    return False


# Called each time a packet is received via Scapy
def scapyPacketCallback(scapy_packet):
    global packets_this_run
    global _time_elapsed
    global start_time

    if processScapyPacket(scapy_packet) == 1:
        packets_this_run += 1
        print("packets this run: " + str(packets_this_run))
        print("time this run: " + str(time.time() - start_time))


# Takes a scapy packet and returns a packet object usable by ui
def processScapyPacket(scapy_packet):
    global _packets
    global _orderedPackets
    global start_time
    global _time_elapsed

    # If IPv4
    if scapy_packet.haslayer("IP"):
        ver, header_length, dscp, ecn, total_len, identification, flags_r, flags_df, flags_mf, fragment_offset, ttl, proto, header_checksum, src, target, data = spf.scapy_ipv4_packet(scapy_packet)

        ipv4Entry = {}

        # Number of packet
        ipv4Entry["no"] = len(_orderedPackets)
        # Time packet was received 
        ipv4Entry["time"] = round(scapy_packet.time - start_time + _time_elapsed, 3)

        ipv4Entry["ver"] = ver
        ipv4Entry["header_length"] = header_length

        ipv4Entry["dscp"] = dscp
        ipv4Entry["ecn"] = ecn
        ipv4Entry["total_length"] = total_len
        ipv4Entry["identification"] = identification
        ipv4Entry["flags_r"] = flags_r
        ipv4Entry["flags_df"]= flags_df
        ipv4Entry["flags_mf"]= flags_mf
        ipv4Entry["fragment_offset"] = fragment_offset

        ipv4Entry["ttl"] = ttl
        ipv4Entry["proto"] = proto

        ipv4Entry["header_checksum"] = header_checksum

        ipv4Entry["src"] = src
        ipv4Entry["target"] = target


        if scapy_packet.haslayer("ICMP"):
            icmp_type, icmp_code, icmp_checksum, icmp_data = spf.scapy_icmp_packet(scapy_packet)
            # Create dictionary entry for icmp packet
            icmpEntry = {}
            icmpEntry["type"] = icmp_type
            icmpEntry["code"] = icmp_code
            icmpEntry["checksum"] = icmp_checksum
            icmpEntry["data"] = icmp_data

            # Contains payload of ip packet as a dictionary
            ipv4Entry["payload"] = icmpEntry
        
        elif scapy_packet.haslayer("TCP"):
            tcp_src_port, tcp_dest_port, tcp_sequence, tcp_acknowledgement, tcp_offset, tcp_reserved, tcp_flag_cwr, tcp_flag_ece, tcp_flag_urg, tcp_flag_ack, tcp_flag_psh, tcp_flag_rst, tcp_flag_syn, tcp_flag_fin, tcp_window, tcp_checksum, tcp_urgent_pointer, tcp_data = spf.scapy_tcp_segment(scapy_packet)
                
            # Create dictionary entry for tcp packet
            tcpEntry = {}
            tcpEntry["src_port"] = tcp_src_port
            tcpEntry["dest_port"] = tcp_dest_port
            tcpEntry["sequence"] = tcp_sequence
            tcpEntry["acknowledgement"] = tcp_acknowledgement
                
            tcpEntry["offset"] = tcp_offset
            tcpEntry["reserved"] = tcp_reserved
            tcpEntry["flag_cwr"] = tcp_flag_cwr
            tcpEntry["flag_ece"] = tcp_flag_ece


            tcpEntry["flag_urg"] = tcp_flag_urg
            tcpEntry["flag_ack"] = tcp_flag_ack
            tcpEntry["flag_psh"] = tcp_flag_psh
            tcpEntry["flag_rst"] = tcp_flag_rst
            tcpEntry["flag_syn"] = tcp_flag_syn
            tcpEntry["flag_fin"] = tcp_flag_fin

            tcpEntry["window"] = tcp_window
            tcpEntry["checksum"] = tcp_checksum
            tcpEntry["urgent_pointer"] = tcp_urgent_pointer
                

            tcpEntry["data"] = tcp_data

            # Contains payload of ip packet as a dictionary
            ipv4Entry["payload"] = tcpEntry

        # UDP packet
        elif scapy_packet.haslayer("UDP"):
            udp_src_port, udp_dest_port, udp_size, udp_checksum, udp_data = spf.scapy_udp_segment(scapy_packet)
                
            # Create dictionary entry for udp packet
            udpEntry = {}
            udpEntry["src_port"] = udp_src_port
            udpEntry["dest_port"] = udp_dest_port
            udpEntry["size"] = udp_size

            udpEntry["checksum"] = udp_checksum

            udpEntry["data"] = udp_data

            # Contains payload of ip packet as a dictionary
            ipv4Entry["payload"] = udpEntry
            
        # Other type of Transport Layer packet
        else:
            print("Unrecognized Transport Layer packet")
            ipv4Entry["payload"] = "not unpacked"


        print("PACKET")
        print(scapy_packet.show)
        print("PACKET DICT")
        print(ipv4Entry)
        storePacket(ipv4Entry, _packets)
    

    # Other type of Network Layer Packet
    else:
        print("Unrecognized Network Layer Packet")
        return 0



    return 1



# PROCESSING PACKETS / STATISTICS FUNCTIONS

# Stores a dictionary representing a packet in a provided list of packets
def storePacket(packetEntry, packetList):
    global _orderedPackets

    if packetEntry["ver"] == 4:
        #print("Storing IPv4 Packet")

        src = packetEntry["src"]
        target = packetEntry["target"]

        # Store packet in Senders > Sender IP > Receiver IP. Create dict entries as needed
        if src in packetList[0]:
            if target not in packetList[0][src]:
                packetList[0][src][target] = []
        else:
            packetList[0][src] = {}
            packetList[0][src][target] = []

        # Store packet in Receivers > Receiver IP > Sender IP. Create dict entries as needed
        if target in packetList[1]:
            if src not in packetList[1][target]:
               packetList[1][target][src] = [] 
        else:
            packetList[1][target] = {}
            packetList[1][target][src] = []

        # Now, store the packet in sender and receiver dicts
        packetList[0][src][target].append(packetEntry)
        packetList[1][target][src].append(packetEntry)


        # Store the packet in ordered list
        _orderedPackets.append(packetEntry)

        # Send message to update ui with new packet
        SendMessageLocal("ui", packetEntry)


# Takes the list of packets, two ip addresses and a dir (to/from/both), returns a list of filtered packets
def getFilteredList(ip1, dir, ip2):
    global _orderedPackets
    global _packets

    # The list to be sent back to ui
    send_list = []

    # If no filters given, return the whole ordered list
    if not ip1 and not ip2:
        print("No filters, sending whole list")
        return _orderedPackets

    # If ip1 is given but not ip2
    elif ip1 and not ip2:
        # ip1 -> anyone
        if dir == "to":
            # ip1 has sent packets, put all of them into a list to send back
            lst = _packets[0]
            if ip1 in lst:
                for ip in _packets[0][ip1]:
                    for packet in _packets[0][ip1][ip]:
                        send_list.append(packet)
                
            print("{} -> anyone".format(ip1))      

        # ip1 <- anyone
        elif dir == "from":
            # ip1 has received packets, put all of them into a list to send back
            if ip1 in _packets[1]:
                for ip in _packets[1][ip1]:
                    for packet in _packets[1][ip1][ip]:
                        send_list.append(packet)

            print("{} <- anyone".format(ip1))

        # ip1 <-> anyone
        elif dir == "both":
            # ip1 has sent packets, put all of them into a list to send back
            if ip1 in _packets[0]:
                for ip in _packets[0][ip1]:
                    for packet in _packets[0][ip1][ip]:
                        send_list.append(packet)
                
            # ip1 has received packets, put all of them into a list to send back
            if ip1 in _packets[1]:
                for ip in _packets[1][ip1]:
                    for packet in _packets[1][ip1][ip]:
                        send_list.append(packet)

            print("{} <-> anyone".format(ip1))

        # If no direction given, return whole ordered list
        else:
            print("No dir given, sending whole list (THIS SHOULDN'T HAPPEN)")
            return _orderedPackets


    # If ip2 is given but not ip1
    elif ip2 and not ip1:

        # anyone -> ip2
        if dir == "to":
            # ip2 has received packets, put all of them into a list to send back
            if ip2 in _packets[1]:
                for ip in _packets[1][ip2]:
                    for packet in _packets[1][ip2][ip]:
                        send_list.append(packet)

            print("anyone -> {}".format(ip2))   

        # anyone <- ip2
        elif dir == "from":
            # ip2 has sent packets, put all of them into a list to send back
            if ip2 in _packets[0]:
                for ip in _packets[0][ip2]:
                    for packet in _packets[0][ip2][ip]:
                        send_list.append(packet)

            print("anyone <- {}".format(ip2))

        # anyone <-> ip2
        elif dir == "both":
            # ip2 has received packets, put all of them into a list to send back
            if ip2 in _packets[1]:
                for ip in _packets[1][ip2]:
                    for packet in _packets[1][ip2][ip]:
                        send_list.append(packet)
                
            # ip2 has sent packets, put all of them into a list to send back
            if ip2 in _packets[0]:
                for ip in _packets[0][ip2]:
                    for packet in _packets[0][ip2][ip]:
                        send_list.append(packet)

            print("anyone <-> {}".format(ip2))
            #return send_list

        # If no direction given, return whole ordered list
        else:
            print("No dir given, sending whole list (THIS SHOULDN'T HAPPEN)")
            return _orderedPackets


    # If both ips are given
    elif ip1 and ip2:
        # ip1 -> ip2
        if dir == "to":
            if ip1 in _packets[0]:
                if ip2 in _packets[0][ip1]:
                    for packet in _packets[0][ip1][ip2]:
                        send_list.append(packet)

            print("{} -> {}".format(ip1, ip2))
        
        # ip1 <- ip2
        elif dir == "from":
            if ip1 in _packets[1]:
                if ip2 in _packets[1][ip1]:
                    for packet in _packets[1][ip1][ip2]:
                        send_list.append(packet)

            print("{} <- {}".format(ip1, ip2))
        
        # ip1 <-> ip2
        elif dir == "both":
            if ip1 in _packets[0]:
                if ip2 in _packets[0][ip1]:
                    for packet in _packets[0][ip1][ip2]:
                        send_list.append(packet)

            if ip1 in _packets[1]:
                if ip2 in _packets[1][ip1]:
                    for packet in _packets[1][ip1][ip2]:
                        send_list.append(packet)

            print("{} <-> {}".format(ip1, ip2))

        # If no direction given, return whole ordered list
        else:
            print("No dir given, sending whole list (THIS SHOULDN'T HAPPEN)")
            return _orderedPackets

    # Return send_list in order
    return orderList(removeDuplicates(send_list))


# Takes a list of packets and returns them in chronological order
def orderList(lst):
    
    # Unordered List
    u_lst = lst
    # Ordered List
    o_lst = []

    # Lowest no. value in the current iteration
    lowestNo = None
    # Index of packet with lowest no. value in current iteration
    lowestIndex = None

    # Handle empty list
    if len(u_lst) == 0:
        return []
    else:
        # Loop through unordered list until all packets have been moved to ordered list
        while len(u_lst) > 0:
            # Init lowest no entry to first entry in unordered list
            lowestNo = u_lst[0]["no"]
            lowestIndex = 0
            # Search through unordered list to find lowest no entry
            for i in range(len(u_lst)):
                # If a lower no is found, update vars
                if u_lst[i]["no"] < lowestNo:
                    lowestNo = u_lst[i]["no"]
                    lowestIndex = i

            # Once finished searching unordered list, move lowest entry to ordered list
            pkt = u_lst[lowestIndex]
            o_lst.append(pkt)
            u_lst.pop(lowestIndex)
            

    return o_lst


# Takes a list of packets and removes duplicates (packets with same no) - only needed for internal processes where src = dst
def removeDuplicates(lst):
    # List with potential duplicates
    d_lst = lst
    # List with all unique packets
    u_lst = []

    print(d_lst)
    print(len(d_lst))

    # Handle empty list
    if len(d_lst) == 0:
        return []
    else:
        for d_pkt in d_lst:
            # Placeholder for unique packet
            pkt = d_pkt
            # Loop through unique list to see if a duplicate exists
            for u_pkt in u_lst:
                if d_pkt["no"] == u_pkt["no"]:
                    # If packet is not unique, remove it from placeholder
                    pkt = None
                    break

            if pkt is not None:
                u_lst.append(pkt)

    return u_lst



# Generats stats based on given IP (how many packets sent/received, who to, proto percentage)
def generateStats(ip=_settings["current interface"][1]):
    global _packets

    # Dictionary containing number of packets sent to and received from each ip
    stats = []
    # Who the ip has sent packets to
    sent_to = {}
    # Who the ip has received packets from
    received_from = {}


    # Get number of packets sent to/from host and other ips

    # Look through sender list
    if ip in _packets[0]:
        print("IP sent packets")
        # Pointer for ip's entry in sender list
        pointer = _packets[0][ip]
        for addr in pointer:
            # Number of packets, number of times each protocol used (network, transport layer)
            details = {}
            # Total number of packets sent from ip to this addr
            details["total"] = len(pointer[addr])
            # Number of ipv4 packets
            details["ipv4"] = 0
            # Number of tcp packets
            details["tcp"] = 0
            # Number of udp packets
            details["udp"] = 0
            # Number of icmp packets
            details["icmp"] = 0

            # Loop through each packet sent from ip to this addr
            for packet in pointer[addr]:
                # Network Layer
                if packet["ver"] == 4:
                    details["ipv4"] += 1
                # Transport Layer (ICMP is technically network layer)
                if packet["proto"] == 1:
                    details["icmp"] += 1
                elif packet["proto"] == 6:
                    details["tcp"] += 1
                elif packet["proto"] == 17:
                    details["udp"] += 1


            # Store details in the dictionary under ip key
            sent_to[addr] = details
    
    stats.append(sent_to)



    # Look through receiver list
    if ip in _packets[1]:
        print("IP received packets")
        # Pointer for ip's entry in receiver list
        pointer = _packets[1][ip]
        for addr in pointer:

            # Number of packets, number of times each protocol used (network, transport layer)
            details = {}
            # Total number of packets sent to ip from this addr
            details["total"] = len(pointer[addr])
            # Number of ipv4 packets
            details["ipv4"] = 0
            # Number of tcp packets
            details["tcp"] = 0
            # Number of udp packets
            details["udp"] = 0
            # Number of icmp packets
            details["icmp"] = 0

            # Loop through each packet sent to ip from this addr
            for packet in pointer[addr]:
                # Network Layer
                if packet["ver"] == 4:
                    details["ipv4"] += 1
                # Transport Layer (ICMP is technically network layer)
                if packet["proto"] == 1:
                    details["icmp"] += 1
                elif packet["proto"] == 6:
                    details["tcp"] += 1
                elif packet["proto"] == 17:
                    details["udp"] += 1


            # Store details in the dictionary under ip key
            received_from[addr] = details


    stats.append(received_from)

    return stats



# SETTINGS/CONTROL FUNCTIONS

# Takes a dict of new values for settings and updates settings
def updateSettings(new_settings):
    global _settings
    for key in new_settings:
        if key in _settings:
            _settings[key] = new_settings[key]


# Clears all packets from memory
def resetData():
    global _packets
    global _orderedPackets
    global _time_elapsed

    global start_time
    global packets_this_run
    
    # A list of received packets in order
    _orderedPackets = []

    # Tuple of sender and receiver IPs (For easier searching, each packet exists in both)
    senderIPs = {}
    receiverIPs = {}
    _packets = [senderIPs, receiverIPs]

    _time_elapsed = 0

    # Might be redundant, reset just in case
    # Time when sniffing starts (temp value- gets updated at start of a run)
    start_time = time.time()
    # Packets gathered in current run
    packets_this_run = 0


# Messaging system (for when multiple threads are active)
#Searches through message buffer for the intended message
#Can do on client OR server
#Name is the key for key value pair
def GetMessage(name):
    global _messages
    global _mesLock

    with _mesLock:
        if not name in _messages:
            return None
        mesList = _messages[name]
        if mesList.empty():
            return None
        mes = mesList.get()

    return mes


def SendMessageLocal(name, mes):
    global _messages
    global _mesLock

    with _mesLock:
        if not name in _messages:
            _messages[name] = queue.Queue()
        _messages[name].put(mes)



# EXPERIMENTAL FUNCTIONS
# NOTE: Run this on a separate thread to prevent blocking
# Given ip address, return Fully Qualified Domain Name (FQDN)
def get_fqdn(ip):
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return host
    except socket.herror:
        return f"Could not resolve FQDN for {ip}"
    except Exception as e:
        return str(e)