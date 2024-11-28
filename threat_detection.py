from collections import defaultdict
import time

ICMP_FLOOD_THRESHOLD = 100  # Number of packets to trigger warning
SYN_FLOOD_THRESHOLD = 100  # Number of packets to trigger warning
PORT_SCANNING_THRESHOLD = 20  # Number of ports to trigger warning

# Logs for scans and alerts
scan_log = defaultdict(list)
alert_log_port_scanning = defaultdict(float)
connection_attempts = defaultdict(lambda: {'SYN': 0, 'ACK': 0})
alert_log_syn_flood = defaultdict(float)
icmp_count = defaultdict(int)
alert_log_icmp_flood = defaultdict(float)

def detect_port_scanning(packet, timestamp):
    """
    Detects potential port scanning by tracking unique destination ports for a source IP.
    """
    src_ip = packet['src_ip']
    dst_ip = packet['dst_ip']
    dst_port = packet['dst_port']
    flags = packet['flags']
    
    if flags & 0x02:  # SYN flag set
        scan_log[src_ip].append((dst_ip, dst_port, timestamp))
        scan_log[src_ip] = [
            entry for entry in scan_log[src_ip] if timestamp - entry[2] <= 10
        ]
        unique_ports = len(set(entry[1] for entry in scan_log[src_ip]))
        if unique_ports > PORT_SCANNING_THRESHOLD:
            if timestamp - alert_log_port_scanning.get(src_ip, 0) > 10:
                message = f"Potential port scan detected from {src_ip} to {dst_ip}"
                print(message)
                alert_log_port_scanning[src_ip] = timestamp
                return message

def detect_syn_flood(packet, timestamp):
    """
    Detects potential SYN flood attacks by monitoring SYN and ACK counts.
    """
    src_ip = packet['src_ip']
    flags = packet['flags']
    if flags & 0x02:  # SYN flag
        connection_attempts[src_ip]['SYN'] += 1
    elif flags & 0x10:  # ACK flag
        connection_attempts[src_ip]['ACK'] += 1

    syn_count = connection_attempts[src_ip]['SYN']
    ack_count = connection_attempts[src_ip]['ACK']
    if syn_count > SYN_FLOOD_THRESHOLD and syn_count > ack_count * 3:
        if timestamp - alert_log_syn_flood[src_ip] > 10:
            message = f"Potential SYN flood detected from {src_ip}"
            print(message)
            alert_log_syn_flood[src_ip] = timestamp
            return message

def detect_icmp_flood(packet, timestamp):
    """
    Detects potential ICMP flood attacks by counting ICMP Echo Requests from a source IP.
    """
    if packet['icmp_type'] == 8:  # ICMP Echo Request
        src_ip = packet['src_ip']
        icmp_count[src_ip] += 1
        if icmp_count[src_ip] > ICMP_FLOOD_THRESHOLD:
            if timestamp - alert_log_icmp_flood[src_ip] > 10:
                message = f"Potential ICMP flood detected from {src_ip}"
                print(message)
                alert_log_icmp_flood[src_ip] = timestamp
                return message
