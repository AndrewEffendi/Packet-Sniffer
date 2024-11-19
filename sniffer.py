import argparse
import socket
import struct
import textwrap
import time
from flask import Flask, render_template, render_template_string, request, jsonify
import threading

# Initialize Flask app
app = Flask(__name__)

# Initialize
sniffing_thread = None
is_sniffing = False
src_ip = None  # Global variable to store the source IP
packet_type = "all"  # Global variable to store the packet type (default: all)

# Store packet data
packet_data = []
packet_detail = []

# Initialize the start time at the beginning of your program
start_time = time.time()  # Capture the start time

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

def update_packet_detail(raw_data):
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
    packet_detail.append('<br>'.join(packet_info))

def update_packet_data(raw_data):
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    packet_info = {}

    # Calculate the elapsed time in seconds since the program started (6 d.p.)
    elapsed_time = round(time.time() - start_time, 6)

    # Initialize packet_info with source, destination, protocol, and elapsed time
    if eth_proto == 0x0800:  # IPv4
        version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
        
        # Check protocol type
        if proto == 1:  # ICMP
            packet_info['protocol_name'] = 'ICMP'
        elif proto == 6:  # TCP
            packet_info['protocol_name'] = 'TCP'
        elif proto == 17:  # UDP
            packet_info['protocol_name'] = 'UDP'
        
        packet_info['source'] = src_ip
        packet_info['destination'] = target_ip
        packet_info['elapsed_time'] = elapsed_time 
        packet_info['index'] = len(packet_data)
        update_packet_detail(raw_data)

    elif eth_proto == 0x0806:  # ARP
        packet_info['protocol_name'] = 'ARP'
        packet_info['source'] = src_mac
        packet_info['destination'] = dest_mac
        packet_info['elapsed_time'] = elapsed_time 
        packet_info['index'] = len(packet_data)
        update_packet_detail(raw_data)
    
    # Append the current packet info to the list
    packet_data.append(packet_info)

# Main sniffer function
def sniff_packets(protocols, src_ip_filter, pcap_filename):
    global is_sniffing, src_ip, packet_type
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print(src_ip)
    print(packet_type)
    
    with open(pcap_filename, "wb") as pcap_file:
        #write_pcap_global_header(pcap_file)
        print(f"Capturing packets and saving to {pcap_filename}.")
        
        try:
            while is_sniffing:
                raw_data, addr = sniffer.recvfrom(65535)
                timestamp = time.time()

                dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

                 # Parse IPv4 packets
                if eth_proto == 0x0800:  # IPv4
                    version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)

                    if (not protocols or proto in protocols) and (not src_ip_filter or src_ip == src_ip_filter):
                        print("IPv4")
                        update_packet_data(raw_data)

                # Parse ARP packets
                elif eth_proto == 0x0806:  # ARP
                    hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip, _ = arp_packet(data)
                    if (2054 in protocols) and (not src_ip_filter or sender_ip == src_ip_filter):
                        print("arp")
                        update_packet_data(raw_data)

                        #write_pcap_packet(pcap_file, timestamp, raw_data)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            sniffer.close()
            print("Sniffing stopped.")

# Web route to display captured packets
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/packets')
def packets():
    return jsonify({'packets': packet_data, 'details': packet_detail})

@app.route('/start', methods=['POST'])
def start_sniffing():
    global is_sniffing, sniffing_thread, src_ip, packet_type
    data = request.get_json()
    src_ip = data.get('src_ip')  # Get src_ip from the request
    packet_type = data.get('packet_type', 'all')  # Get packet_type, default to 'all'
    if not is_sniffing:
        is_sniffing = True
        protocols = set()
        if packet_type == 'icmp':
            protocols.add(1)  # ICMP
        if packet_type == 'tcp':
            protocols.add(6)  # TCP
        if packet_type == 'udp':
            protocols.add(17)  # UDP
        if packet_type == 'arp':
            protocols.add(2054)  # ARP
        if packet_type == 'all':
            protocols = {1, 6, 17, 2054}
        sniffing_thread = threading.Thread(target=sniff_packets, args=(protocols, src_ip, "web_capture.pcap",))
        sniffing_thread.start()
        status_message = f"Sniffing started with source IP: {src_ip or 'any'} and packet type: {packet_type}"
        return jsonify({"status": status_message})
    return jsonify({"status": "Sniffing already running"})

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    global is_sniffing, packet_data, packet_detail
    if is_sniffing:
        packet_data = []
        packet_detail = []
        is_sniffing = False
        sniffing_thread.join()
        return jsonify({"status": "Sniffing stopped"})
    return jsonify({"status": "Sniffing was not running"})

# Argument parser to specify protocols and source IP filter
def main():
    # Start the app
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    main()
