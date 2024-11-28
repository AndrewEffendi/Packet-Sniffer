import argparse
import socket
import textwrap
import time
from flask import Flask, render_template, render_template_string, request, jsonify
import threading

import pcap_utils
import unpack_utils
import packet_utils
import threat_detection
from traffic_analysis import TrafficAnalyzer

# Initialize Flask app
app = Flask(__name__)

# Initialize
sniffing_thread = None
is_sniffing = False
packet_type = "all"  # Global variable to store the packet type (default: all)
start_time = -1
traffic_analyzer = TrafficAnalyzer()

# Store packet data
packet_data = []
packet_detail = []
threat_log = []

# default
DEFAULT_PCAP_FILENAME = 'captured_packets'


def update_packet_detail(raw_data):
    """
    Update packet details for display in the web interface.
    """
    packet_info = packet_utils.build_packet_info(raw_data)
    packet_detail.append('<br>'.join(packet_info))

def update_packet_data(timestamp, raw_data):
    """
    Process and store packet metadata including elapsed time and size.
    """
    global start_time
    packet_overview = {}

    # if start time empty, this packet is the first packet, with start time 0.0
    if(start_time == -1):
        start_time = timestamp
        traffic_analyzer.start_capture(timestamp)
    
    # Calculate the elapsed time in seconds since the program started (6 d.p.)
    elapsed_time = timestamp - start_time
    formatted_elapsed_time = f"{elapsed_time:.6f}"

    dst_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)
    index = len(packet_data)

    # update total bytes captured
    packet_size = len(raw_data)
    traffic_analyzer.update_bandwidth_stats(packet_size, elapsed_time)

    if eth_proto == 0x0800:  # IPv4
        packet_overview = packet_utils.build_IPv4_overview(raw_data, index, formatted_elapsed_time)
        update_packet_detail(raw_data)
        version, header_length, ttl, proto, src_ip, dst_ip, data = unpack_utils.ipv4_packet(data)
        if proto == 6:
            traffic_analyzer.update_protocol_stats('TCP')
        elif proto == 17:
            traffic_analyzer.update_protocol_stats('UDP')
        elif proto == 1:
            traffic_analyzer.update_protocol_stats('ICMP')
        else:
            traffic_analyzer.update_protocol_stats('Other')
        traffic_analyzer.update_ip_stats(src_ip, dst_ip, packet_size)
    elif eth_proto == 0x0806:  # ARP
        packet_overview = packet_utils.build_ARP_overview(raw_data, index, formatted_elapsed_time)
        update_packet_detail(raw_data)
        traffic_analyzer.update_protocol_stats('ARP')
        hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dst_mac, dst_ip, _ = unpack_utils.arp_packet(data)
        traffic_analyzer.update_ip_stats(src_ip, dst_ip, packet_size)
    else:
        traffic_analyzer.update_protocol_stats('Other')
    
    packet_data.append(packet_overview)

def run_threat_detection_IPv4(proto, data, src_ip, dst_ip, timestamp):
    """
    Analyze IPv4 packets for potential threats like floods or scans.
    """
    if proto == 1:  # ICMP
        icmp_type, code, checksum, data = unpack_utils.icmp_packet(data)
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'icmp_type': icmp_type
        }
        icmp_flood_threat = threat_detection.detect_icmp_flood(packet_info, timestamp)
        # add to threat log if there is potential threat
        if (icmp_flood_threat):
            threat_log.append(icmp_flood_threat)
            
    if proto == 6: #TCP
        src_port, dst_port, sequence, acknowledgment, offset, flags, data = unpack_utils.tcp_segment(data)

        # Build a structured packet dictionary
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'flags': flags  # Use flags parsed from TCP
        }

        # Pass structured data to threat detection
        port_scanning_threat = threat_detection.detect_port_scanning(packet_info, timestamp)
        syn_flood_threat = threat_detection.detect_syn_flood(packet_info, timestamp)

        # add to threat log if there is potential threat
        if (port_scanning_threat):
            threat_log.append(port_scanning_threat)
        if (syn_flood_threat):
            threat_log.append(syn_flood_threat)

# Main sniffer function
def sniff_packets(protocols, src_ip_filter, dst_ip_filter, pcap_filename, min_packet_size=None, max_packet_size=None):
    """
    Capture and process packets with optional filters and save to PCAP.
    """
    global is_sniffing, packet_type, start_time
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    # init start time
    start_time = -1
    
    if pcap_filename == '':
        pcap_filename = DEFAULT_PCAP_FILENAME
    pcap_filename_ext = pcap_filename + '.pcap'
    with open(pcap_filename_ext, "wb") as pcap_file:
        pcap_utils.write_pcap_global_header(pcap_file)
        print(f"Capturing packets and saving to {pcap_filename}.pcap")
        
        try:
            while is_sniffing:
                raw_data, addr = sniffer.recvfrom(65535)
                timestamp = time.time()

                # filter the packet size
                packet_size = len(raw_data)
                if (min_packet_size is not None and packet_size < int(min_packet_size)) or \
           (max_packet_size is not None and packet_size > int(max_packet_size)):
                    continue

                dst_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)

                 # Parse IPv4 packets
                if eth_proto == 0x0800:  # IPv4
                    version, header_length, ttl, proto, src_ip, dst_ip, data = unpack_utils.ipv4_packet(data)

                    if ((not protocols or proto in protocols) 
                            and not (src_ip == '127.0.0.1' and dst_ip == '127.0.0.1') # dont include loopback address
                            and (not src_ip_filter or src_ip == src_ip_filter) 
                            and (not dst_ip_filter or dst_ip == dst_ip_filter)):
                        update_packet_data(timestamp, raw_data)
                        pcap_utils.write_pcap_packet(pcap_file, timestamp, raw_data)
                        
                        # run threat detection
                        run_threat_detection_IPv4(proto, data, src_ip, dst_ip, timestamp)

                # Parse ARP packets
                elif eth_proto == 0x0806:  # ARP
                    hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dst_mac, dst_ip, _ = unpack_utils.arp_packet(data)
                    if ((2054 in protocols) 
                            and not (src_ip == '127.0.0.1' and dst_ip == '127.0.0.1') # dont include loopback address
                            and (not src_ip_filter or src_ip == src_ip_filter) 
                            and (not dst_ip_filter or dst_ip == dst_ip_filter)):
                        update_packet_data(timestamp, raw_data)
                        pcap_utils.write_pcap_packet(pcap_file, timestamp, raw_data)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            sniffer.close()
            print("Sniffing stopped.")

 
@app.route('/')
def index():
    """
    Render the main web interface of the packet sniffer.
    """
    return render_template('index.html')

@app.route('/packets')
def packets():
    """
    Provide JSON of captured packets, details, and threat logs.
    """
    return jsonify({'packets': packet_data, 'details': packet_detail, 'threats': threat_log})

@app.route('/start', methods=['POST'])
def start_sniffing():
    """
    Start packet sniffing with specified filters and configurations.
    """
    global is_sniffing, sniffing_thread, packet_type, packet_data, packet_detail, threat_log
    data = request.get_json()
    src_ip = data.get('src_ip')  # Get src_ip from the request
    dst_ip = data.get('dst_ip') # Get dest_ip from the request
    pcap_filename = data.get('pcap_filename')
    packet_types = data.get('packet_types', '[]')
    min_packet_size = data.get('min_packet_size')
    max_packet_size = data.get('max_packet_size')
    if min_packet_size:
        min_packet_size = int(min_packet_size)
    else:
        min_packet_size = None
    if max_packet_size:
        max_packet_size = int(max_packet_size)
    else:
        max_packet_size = None 
        
    if not is_sniffing:
        is_sniffing = True
        packet_data = []
        packet_detail = []
        threat_log = []
        traffic_analyzer.reset_stats()
        protocols = set()
        if 'icmp' in packet_types:
            protocols.add(1)  # ICMP
        if 'tcp' in packet_types:
            protocols.add(6)  # TCP
        if 'udp' in packet_types:
            protocols.add(17)  # UDP
        if 'arp' in packet_types:
            protocols.add(2054)  # ARP
        if packet_types == []: 
            protocols = {1, 6, 17, 2054} #all
        sniffing_thread = threading.Thread(target=sniff_packets, args=(protocols, src_ip, dst_ip, pcap_filename, min_packet_size, max_packet_size))
        sniffing_thread.start()
        status_message = f"Sniffing started with source IP: {src_ip or 'any'}, destination IP: {dst_ip or 'any'} and packet type: {packet_types}"
        return jsonify({"status": status_message})
    return jsonify({"status": "Sniffing already running"})

@app.route('/stop', methods=['POST'])
def stop_sniffing():
    """
    Stop packet sniffing and terminate the capturing thread.
    """
    global is_sniffing
    if is_sniffing:
        is_sniffing = False
        sniffing_thread.join()
        return jsonify({"status": "Sniffing stopped"})
    return jsonify({"status": "Sniffing was not running"})

@app.route('/bandwidth')
def get_bandwidth():
    """
    Provide real-time bandwidth usage statistics.
    """
    return jsonify(traffic_analyzer.get_bandwidth_stats(is_sniffing))

@app.route('/protocol-stats')
def get_protocol_stats():
    """
    Provide statistics on captured packets by protocol type.
    """
    return jsonify(traffic_analyzer.get_protocol_stats())

@app.route('/top-talkers')
def get_top_talkers():
    """
    Provide statistics on top source and destination addresses.
    """
    return jsonify(traffic_analyzer.get_top_talkers())

@app.route('/Update_line_chart')
def get_throughput_data(): 
    """
    Provide real-time throughput data for chart visualization.
    """
    return jsonify(traffic_analyzer.get_throughput_data(is_sniffing))

def main():
    """
    Initialize and run the Flask application.
    """
    # Start the app
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    # suppress Flask’s built-in development server
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    # run main function
    main()
