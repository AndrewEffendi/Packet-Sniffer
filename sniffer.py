import argparse
import socket
import struct
import textwrap
from flask import Flask, render_template, render_template_string, jsonify
import threading

# Initialize Flask app
app = Flask(__name__)

# Store packet data
packet_data = []

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
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]

# UDP segment unpacking
def udp_segment(data):
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])
    return src_port, dest_port, length, checksum, data[8:]

def update_packet_data(raw_data):
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    packet_info = [
        f'<strong>Ethernet Frame:</strong>',
        f'  - Destination MAC: {dest_mac}',
        f'  - Source MAC: {src_mac}',
        f'  - Protocol: {eth_proto}'
    ]
    
    if eth_proto == 0x0800:  # IPv4
        version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
        packet_info.append(f'<strong>IPv4 Packet:</strong>')
        packet_info.append(f'    - Version: {version}')
        packet_info.append(f'    - Header Length: {header_length}')
        packet_info.append(f'    - TTL: {ttl}')
        packet_info.append(f'    - Protocol: {proto}')
        packet_info.append(f'    - Source IP: {src_ip}')
        packet_info.append(f'    - Target IP: {target_ip}')
        
        if proto == 1:  # ICMP
            icmp_type, code, checksum, data = icmp_packet(data)
            packet_info.append(f'<strong>ICMP Packet:</strong>')
            packet_info.append(f'    - Type: {icmp_type}')
            packet_info.append(f'    - Code: {code}')
            packet_info.append(f'    - Checksum: {checksum}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + format_multi_line(data.hex()) + '</pre>')

        elif proto == 6:  # TCP
            src_port, dest_port, sequence, acknowledgment, offset, data = tcp_segment(data)
            packet_info.append(f'<strong>TCP Segment:</strong>')
            packet_info.append(f'    - Source Port: {src_port}')
            packet_info.append(f'    - Destination Port: {dest_port}')
            packet_info.append(f'    - Sequence: {sequence}')
            packet_info.append(f'    - Acknowledgment: {acknowledgment}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + format_multi_line(data.hex()) + '</pre>')

        elif proto == 17:  # UDP
            src_port, dest_port, length, checksum, data = udp_segment(data)
            packet_info.append(f'<strong>UDP Segment:</strong>')
            packet_info.append(f'    - Source Port: {src_port}')
            packet_info.append(f'    - Destination Port: {dest_port}')
            packet_info.append(f'    - Length: {length}')
            packet_info.append(f'    - Checksum: {checksum}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + format_multi_line(data.hex()) + '</pre>')

    elif eth_proto == 0x0806:  # ARP
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip, _ = arp_packet(data)
        packet_info.append(f'<strong>ARP Packet:</strong>')
        packet_info.append(f'    - Hardware Type: {hw_type}')
        packet_info.append(f'    - Protocol Type: {proto_type}')
        packet_info.append(f'    - Hardware Size: {hw_size}')
        packet_info.append(f'    - Protocol Size: {proto_size}')
        packet_info.append(f'    - Opcode: {opcode}')
        packet_info.append(f'    - Sender MAC: {sender_mac}')
        packet_info.append(f'    - Sender IP: {sender_ip}')
        packet_info.append(f'    - Target MAC: {target_mac}')
        packet_info.append(f'    - Target IP: {target_ip}')

    # Append the current packet info to the list
    packet_data.append('<br>'.join(packet_info))



# Main sniffer function
def sniff(protocols, src_ip_filter):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # Parse IPv4 packets
        if eth_proto == 0x0800:  # IPv4
            version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)

            if (not protocols or proto in protocols) and (not src_ip_filter or src_ip == src_ip_filter):
                update_packet_data(raw_data)

        # Parse ARP packets
        elif eth_proto == 0x0806:  # ARP
            hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip, _ = arp_packet(data)
            if (2054 in protocols) and (not src_ip_filter or sender_ip == src_ip_filter):
                update_packet_data(raw_data)

# Web route to display captured packets
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/packets')
def packets():
    return jsonify({'packets': packet_data})

# Argument parser to specify protocols and source IP filter
def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer for specific protocols (ICMP, TCP, UDP, ARP).')
    parser.add_argument('--protocols', type=str, nargs='*', choices=['icmp', 'tcp', 'udp', 'arp'],
                        help='Specify which protocols to sniff: icmp, tcp, udp, arp')
    parser.add_argument('--src_ip', type=str, help='Specify a source IP to filter by')

    args = parser.parse_args()

    # Create a set of protocols based on user input
    protocols = set()
    if args.protocols:
        if 'icmp' in args.protocols:
            protocols.add(1)  # ICMP
        if 'tcp' in args.protocols:
            protocols.add(6)  # TCP
        if 'udp' in args.protocols:
            protocols.add(17)  # UDP
        if 'arp' in args.protocols:
            protocols.add(2054)  # ARP
    else:
        # Default to all protocols if none specified
        protocols = {1, 6, 17, 2054}

    # Start sniffing in a separate thread
    threading.Thread(target=sniff, args=(protocols, args.src_ip)).start()
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    main()
