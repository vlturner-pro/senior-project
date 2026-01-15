# Formats scapy packets to a packet dictionary readable by the program

def scapy_ipv4_packet(scapy_packet):
    # IP layer of packet (pointer)
    ipv4 = scapy_packet["IP"]

    version = ipv4.version
    header_length = ipv4.ihl
    # TOS consists of DSCP and ECN (should). Scapy only gives tos
    tos = ipv4.tos
    # Differentiated Services Code Point
    dscp = tos >> 2
    # Explicit Congestion Notification
    ecn = tos & 3
    total_len = ipv4.len
    identification = ipv4.id
    # Flags consists of R, DF and MF
    flags = ipv4.flags
    flags_r = 0
    flags_df = 0
    flags_mf = 0
    # Reserved flag
    if "R" in flags:
        flags_r = 1
    # Don't Fragment flag
    if "DF" in flags:
        flags_df = 1
    # More Fragments flag
    if "MF" in flags:
        flags_mf = 1
    # Fragment Offset (in bytes)
    fragment_offset = ipv4.frag
    ttl = ipv4.ttl
    # Transport Layer proto
    proto = ipv4.proto
    # Source and target IP
    src = ipv4.src
    target = ipv4.dst
    # Header Checksum
    header_checksum = ipv4.chksum

    #TODO: Check if more layers in packet. If not, use raw?
    data = None

    return version, header_length, dscp, ecn, total_len, identification, flags_r, flags_df, flags_mf, fragment_offset, ttl, proto, header_checksum, src, target, data



def scapy_icmp_packet(scapy_packet):
    # Pointer for ICMP layer of packet
    icmp = scapy_packet["ICMP"]
    icmp_type = icmp.type
    code = icmp.code
    checksum = icmp.chksum
    data = None
    

    # Get raw data, if included in packet
    if scapy_packet.haslayer("Raw"):
        raw = scapy_packet["Raw"]
        data = raw.load


    return icmp_type, code, checksum, data



def scapy_tcp_segment(scapy_packet):
    # Pointer for TCP layer of packet
    tcp = scapy_packet["TCP"]
    src_port = tcp.sport
    dest_port = tcp.dport
    sequence = tcp.seq
    acknowledgement = tcp.ack
    offset = tcp.dataofs
    # Reserved (should always be 0, senders should not set these and receivers should ignore them)
    reserved = tcp.reserved
    # Flags
    flag_cwr = 0
    flag_ece = 0
    flag_urg = 0
    flag_ack = 0
    flag_psh = 0
    flag_rst = 0
    flag_syn = 0
    flag_fin = 0
    if "C" in tcp.flags:
        flag_cwr = 1
    if "E" in tcp.flags:
        flag_ece = 1
    if "U" in tcp.flags:
        flag_urg = 1
    if "A" in tcp.flags:
        flag_ack = 1
    if "P" in tcp.flags:
        flag_psh = 1
    if "R" in tcp.flags:
        flag_rst = 1
    if "S" in tcp.flags:
        flag_syn = 1
    if "F" in tcp.flags:
        flag_fin = 1
    # Window
    # Size of the receive window (in bytes)
    window = tcp.window
    # Checksum
    checksum = tcp.chksum
    # Urgent Pointer (meaningful when URG bit set)
    # If the Urg flag is set, this indicates the last urgent data byte
    urgent_pointer = tcp.urgptr
    data = None

    # Get raw data, if included in packet
    if scapy_packet.haslayer("Raw"):
        raw = scapy_packet["Raw"]
        data = raw.load

    return src_port, dest_port, sequence, acknowledgement, offset, reserved, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent_pointer, data



def scapy_udp_segment(scapy_packet):
    # Pointer for UDP layer of packet
    udp = scapy_packet["UDP"]    
    src_port = udp.sport
    dest_port = udp.dport
    # Size is the total length (in bytes) of the UDP datagram (header + data)
    size = udp.len
    checksum = udp.chksum
    data = None

    # Get raw data, if included in packet
    if scapy_packet.haslayer("Raw"):
        raw = scapy_packet["Raw"]
        data = raw.load

    return src_port, dest_port, size, checksum, data