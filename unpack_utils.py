import struct

# Helper functions for formatting and unpacking
def mac_format(mac_raw):
    return ':'.join(map('{:02x}'.format, mac_raw))

def ipv4_format(ip_raw):
    return '.'.join(map(str, ip_raw))

def format_multi_line(data, size=80):
    return '\n'.join([data[i:i + size] for i in range(0, len(data), size)])

# Ethernet frame unpacking
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return mac_format(dest_mac), mac_format(src_mac), proto, data[14:]

# IPv4 packet unpacking
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = ipv4_format(src)
    target_ip = ipv4_format(target)
    return version, header_length, ttl, proto, src_ip, target_ip, data[header_length:]

# ARP packet unpacking
def arp_packet(data):
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack('! H H B B H', data[:8])
    sender_mac = mac_format(data[8:14])
    sender_ip = ipv4_format(data[14:18])
    target_mac = mac_format(data[18:24])
    target_ip = ipv4_format(data[24:28])
    return hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip, data[28:]

# ICMP packet unpacking
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# TCP segment unpacking
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # Extract the offset (header length)
    flags = offset_reserved_flags & 0x3F       # Extract the last 6 bits for flags
    return src_port, dest_port, sequence, acknowledgment, offset, flags, data[offset:]

# UDP segment unpacking
def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, length, checksum, data[8:]