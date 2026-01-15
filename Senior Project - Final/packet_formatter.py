# Formats raw data from socket into a packet dictionary readable by the program

# Format characters for struct used: s = char, H = unsigned short, x = pad byte, B = unsigned char, L = unsigned long
import struct
import socket
import sys


# Unpack ethernet frame (not needed)
# Frame format: Receiver (6by), Sender (6by), Type (2by), Payload(46-1500by)
# Payload begins byte 14
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return formatted MAC Address 
# bytes_addr is an iterable broken into chunks
# After passing through this function, address format should be: ##:##:##:##:##:## (all letters upper)
def get_mac_addr(bytes_addr):
    # Run each part of the address iterable through format function
    bytes_str = map('{:02x}'.format, bytes_addr)
    # Join address together in proper address format
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr



# Everything in ip packet included except options
# Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    # Bitwise operation, bit shift 4 to the right
    version = version_header_length >> 4
    # Multiply header length words by 4 to get the number of bytes in header (4 bytes per word)
    header_length = (version_header_length & 15) * 4
    # Extract the header into variables
    # [:20] = everything before byte 20 (0 - 19)
    # [20:] = everything after byte 19 (20 - end)
    # First 20 bytes of data [0 - 19]:
    # 8 pad bytes (no value), unsigned byte, unsigned byte, 2 pad bytes (no value) 4 string, 4 string
    # 8 + 1 + 1 + 2 + 4 + 4 = 20 bytes, the four items that aren't pad bytes get stored in the variables as the specified format
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])



    # Byte 1
    dscp_ecn = data[1]
    # Differentiated Services Code Point
    dscp = dscp_ecn >> 2
    # Explicit Congestion Notification
    ecn = dscp_ecn & 3
    #print("dscp: " + str(dscp))
    #print("ecn: " + str(ecn))



    # Bytes 2-3
    # Total Length (in bytes)
    total_len_bytes = data[2:4]
    total_len = int.from_bytes(total_len_bytes, sys.byteorder)

    #print("total_len: " + str(total_len))



    # Bytes 4-5
    ident_bytes = data[4:6]
    # int.from_bytes is similar to struct.unpack
    identification = int.from_bytes(ident_bytes, sys.byteorder)
    #identification, ttl, proto, src, target = struct.unpack('! 4x 2f 2x B B 2x 4s 4s', data[:20])
    #b'' means a sequence of bytes

    
    # Bytes 6-7
    flags_fragment_offset_bytes = data[6:8]
    flags_fragment_offset = int.from_bytes(flags_fragment_offset_bytes, sys.byteorder)
    #print("flags_fragment_offset: " + str(flags_fragment_offset))
    flags = flags_fragment_offset >> 13
    # Reserved flag
    flags_r = flags >> 2
    # Don't Fragment flag
    flags_df = (flags >> 1) & 1
    # More Fragments flag
    flags_mf = flags & 1
    #print("reserved: " + str(flags_r))
    #print("don't fragment: " + str(flags_df))
    #print("more fragments: " + str(flags_mf))

    # Fragment Offset (in bytes)
    fragment_offset = flags_fragment_offset & 8191
    #print("fragment offset: " + str(fragment_offset))



    # Bytes 11-12
    # Header Checksum
    header_checksum_bytes = data[11:13]
    header_checksum = int.from_bytes(header_checksum_bytes, sys.byteorder)

    #print("header_checksum: " + str(header_checksum))

    return version, header_length, dscp, ecn, total_len, identification, flags_r, flags_df, flags_mf, fragment_offset, ttl, proto, header_checksum, ipv4(src), ipv4(target), data[header_length:]


# Returns formatted IPv4 address, with strings joined by dots
def ipv4(addr):
    return '.'.join(map(str, addr))



# TODO: In UI, show icmp type based on icmp code here
# Extended header may be needed (Bytes 4-7)
# Unpacks ICMP packet
def icmp_packet(data):
    # First 4 bytes (header)
    # (Keep bytes in order), unsigned byte (1 byte), unsigned byte (1 byte), unsigned short (2 bytes)
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    return icmp_type, code, checksum, data[4:]




# Unpacks TCP segment (common)
# Gets everything except options
def tcp_segment(data):
    # (Keep bytes in order), unsigned short (2 bytes), unsigned short (2 bytes), unsigned long (4 bytes), unsigned long (4 bytes), unsigned short (2 bytes),
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # Data offset tells how many 32 bit (4 byte) words are in header
    # Multiply by 4 to get the number of bytes in the header
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1




    # Reserved (should always be 0, senders should not set these and receivers should ignore them)
    reserved = (offset_reserved_flags >> 8) & 4
    #print("reserved: " + str(reserved))


    # CWR flag
    flag_cwr = (offset_reserved_flags & 128) >> 7
    #print("CWR flag: " + str(flag_cwr))


    # ECE flag
    flag_ece = (offset_reserved_flags & 64) >> 6
    #print("ECE flag: " + str(flag_ece))



    # Bytes 10-11
    # Window
    # Size of the receive window (in bytes)
    window_bytes = data[10:12]
    window = int.from_bytes(window_bytes, sys.byteorder)
    #print("window: " + str(window))


    # Bytes 12-13
    # Checksum
    checksum_bytes = data[12:14]
    checksum = int.from_bytes(checksum_bytes, sys.byteorder)
    #print("checksum: " + str(checksum))


    # Bytes 14-15
    # Urgent Pointer (meaningful when URG bit set)
    # If the Urg flag is set, this indicates the last urgent data byte
    urgent_pointer_bytes = data[15:16]
    urgent_pointer = int.from_bytes(urgent_pointer_bytes, sys.byteorder)
    #print("urgent_pointer: " + str(urgent_pointer))

    return src_port, dest_port, sequence, acknowledgement, offset, reserved, flag_cwr, flag_ece, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent_pointer, data[offset:]






# Unpacks UDP segment
# Gets everything
def udp_segment(data):
    # (Keep bytes in order), unsigned short (2 bytes), unsigned short (2 bytes), 2 pad bytes, unsigned short (2 bytes)
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])

    # Checksum
    checksum = int.from_bytes(data[4:6])
    #print("checksum: " + str(checksum))

    # Size is the total length (in bytes) of the UDP datagram (header + data)
    return src_port, dest_port, size, checksum, data[8:]






#TODO: Add support for IPv6
