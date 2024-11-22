from collections import defaultdict
import time

ICMP_FLOOD_THRESHOLD = 100 # number of packets to trigger warning
SYN_FLOOD_THRESHOLD = 100 # number of packets to trigger warning
PORT_SCANNING_THRESHOLD = 20 # number of ports to trigger warning

# Log for tracking scans and recent alerts
scan_log = defaultdict(list)  # Keeps track of scanned ports
alert_log_port_scanning = defaultdict(float)  # Keeps track of last alert timestamp per source IP

def detect_port_scanning(packet, timestamp):
    src_ip = packet['src_ip']
    dst_ip = packet['dst_ip']
    dst_port = packet['dst_port']
    flags = packet['flags']  # Extracted TCP flags
    
    # Only track SYN packets
    if flags & 0x02:  # Check if the SYN bit is set
        scan_log[src_ip].append((dst_ip, dst_port, timestamp))
        
        # Remove outdated entries (e.g., older than 10 seconds)
        scan_log[src_ip] = [
            entry for entry in scan_log[src_ip] 
            if timestamp - entry[2] <= 10
        ]

        # Count unique destination ports in the last 10 seconds
        unique_ports = len(set((entry[1] for entry in scan_log[src_ip])))

        # Threshold for detecting a potential port scan
        if unique_ports > PORT_SCANNING_THRESHOLD:  # Adjust the threshold as needed
            # Check if we already alerted about this IP recently
            last_alert_time = alert_log_port_scanning.get(src_ip, 0)
            if timestamp - last_alert_time > 10:  # Alert only if 10+ seconds since the last alert
                message = f"Potential port scan detected from {src_ip} to {dst_ip}"
                print(message)
                alert_log_port_scanning[src_ip] = timestamp  # Update the alert timestamp
                return message


# Track SYN and ACK counts for each source IP
connection_attempts = defaultdict(lambda: {'SYN': 0, 'ACK': 0})

# Track the last time we alerted for a SYN flood for each IP (cooldown)
alert_log_syn_flood = defaultdict(float)  # Stores timestamp of last alert for each IP

def detect_syn_flood(packet, timestamp):
    src_ip = packet['src_ip']
    flags = packet['flags']  # Extracted TCP flags

    # Check if the SYN flag is set (SYN bit = 0x02)
    if flags & 0x02:  # SYN flag set
        connection_attempts[src_ip]['SYN'] += 1
    elif flags & 0x10:  # ACK flag set (0x10 represents ACK flag)
        connection_attempts[src_ip]['ACK'] += 1
    
    # Retrieve SYN and ACK counts for the source IP
    syn_count = connection_attempts[src_ip]['SYN']
    ack_count = connection_attempts[src_ip]['ACK']
    
    # Check for SYN flood conditions
    if syn_count > SYN_FLOOD_THRESHOLD and syn_count > ack_count * 3:  # Threshold: SYN > ACK * 3
        # Check if we already alerted about this IP recently (cooldown period)
        if timestamp - alert_log_syn_flood[src_ip] > 10:  # Only alert if 10+ seconds since last alert
            message = f"Potential SYN flood detected from {src_ip}"
            print(message)
            alert_log_syn_flood[src_ip] = timestamp  # Update the last alert time
            return message

# Dictionary to store packet counts for each IP
icmp_count = defaultdict(int)
# Track the last time we alerted for a SYN flood for each IP (cooldown)
alert_log_icmp_flood = defaultdict(float)  # Stores timestamp of last alert for each IP
def detect_icmp_flood(packet, timestamp):
    if packet['icmp_type'] == 8:  # ICMP Echo Request
        src_ip = packet['src_ip']
        icmp_count[src_ip] += 1
        if icmp_count[src_ip] > ICMP_FLOOD_THRESHOLD:
            if timestamp - alert_log_icmp_flood[src_ip] > 10:  # Only alert if 10+ seconds since last alert
                message = f"Potential ICMP flood detected from {src_ip}"
                print(message)
                alert_log_icmp_flood[src_ip] = timestamp  # Update the last alert time
                return message 

def detect_arp_spoofing(src_mac, dst_ip, timestamp):
    if dst_ip in arp_table and arp_table[dst_ip] != src_mac:
        print(f"ARP Spoofing detected for IP {dst_ip}")
    arp_table[dst_ip] = src_mac
