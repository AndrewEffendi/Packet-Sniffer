import argparse
import socket
import textwrap
import time
from flask import Flask, render_template, render_template_string, request, jsonify
import threading

import pcap_utils
import unpack_utils
import packet_utils

# Initialize Flask app
app = Flask(__name__)

# Initialize
sniffing_thread = None
is_sniffing = False
src_ip = None  # Global variable to store the source IP
packet_type = "all"  # Global variable to store the packet type (default: all)
start_time = -1

# Store packet data
packet_data = []
packet_detail = []

def update_packet_detail(raw_data):
    packet_info = packet_utils.build_packet_info(raw_data)

    # Append the current packet info to the list
    packet_detail.append('<br>'.join(packet_info))

def update_packet_data(timestamp, raw_data):
    global start_time
    packet_overview = {}

    # if start time empty, this packet is the first packet, with start time 0.0
    if(start_time == -1):
        start_time = timestamp
    
    # Calculate the elapsed time in seconds since the program started (6 d.p.)
    elapsed_time = timestamp - start_time
    formatted_elapsed_time = f"{elapsed_time:.6f}"

    dest_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)
    index = len(packet_data)

    # Initialize packet_overview with source, destination, protocol, and elapsed time
    if eth_proto == 0x0800:  # IPv4
        packet_overview = packet_utils.build_IPv4_overview(raw_data, index, formatted_elapsed_time)
        update_packet_detail(raw_data)

    elif eth_proto == 0x0806:  # ARP
        packet_overview = packet_utils.build_ARP_overview(raw_data, index, formatted_elapsed_time)
        update_packet_detail(raw_data)
    
    # Append the current packet info to the list
    packet_data.append(packet_overview)

# Main sniffer function
def sniff_packets(protocols, src_ip_filter, pcap_filename):
    global is_sniffing, src_ip, packet_type, start_time
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print(src_ip)
    print(packet_type)

    # init start time
    start_time = -1
    
    with open(pcap_filename, "wb") as pcap_file:
        pcap_utils.write_pcap_global_header(pcap_file)
        print(f"Capturing packets and saving to {pcap_filename}.")
        
        try:
            while is_sniffing:
                raw_data, addr = sniffer.recvfrom(65535)
                timestamp = time.time()

                dest_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)

                 # Parse IPv4 packets
                if eth_proto == 0x0800:  # IPv4
                    version, header_length, ttl, proto, src_ip, target_ip, data = unpack_utils.ipv4_packet(data)

                    if (not protocols or proto in protocols) and (not src_ip_filter or src_ip == src_ip_filter):
                        print("IPv4")
                        update_packet_data(timestamp, raw_data)
                        pcap_utils.write_pcap_packet(pcap_file, timestamp, raw_data)

                # Parse ARP packets
                elif eth_proto == 0x0806:  # ARP
                    hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, target_mac, target_ip, _ = unpack_utils.arp_packet(data)
                    if (2054 in protocols) and (not src_ip_filter or sender_ip == src_ip_filter):
                        print("arp")
                        update_packet_data(timestamp, raw_data)
                        pcap_utils.write_pcap_packet(pcap_file, timestamp, raw_data)
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
    global is_sniffing, sniffing_thread, src_ip, packet_type, packet_data, packet_detail
    data = request.get_json()
    src_ip = data.get('src_ip')  # Get src_ip from the request
    packet_type = data.get('packet_type', 'all')  # Get packet_type, default to 'all'
    if not is_sniffing:
        is_sniffing = True
        packet_data = []
        packet_detail = []
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
    global is_sniffing
    if is_sniffing:
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
