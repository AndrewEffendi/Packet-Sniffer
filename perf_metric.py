import time
from collections import defaultdict

# Store timestamps of packets for latency calculation
latency_data = defaultdict(list)  # {src_ip: [(timestamp, packet_seq_number)]}

def calculate_latency(packet, timestamp):
    src_ip = packet['src_ip']
    flags = packet['flags']
    seq_num = packet['seq_num']  # TCP sequence number
    
    print(flags)
    # For SYN packet, store the timestamp
    if flags & 0x02:  # SYN flag set
        latency_data[src_ip].append((timestamp, seq_num))
    
    # For SYN-ACK packet, calculate RTT with the SYN request
    elif flags & 0x12 == 0x12:  # SYN and ACK flags set
        if latency_data[src_ip]:
            syn_timestamp, syn_seq_num = latency_data[src_ip].pop(0)
            latency = timestamp - syn_timestamp  # RTT for the SYN-ACK pair
            print(f"Latency from {src_ip}: {latency} seconds")

def calculate_jitter():
    # Calculate jitter (standard deviation of latency) over time for each IP
    for ip, latencies in latency_data.items():
        if len(latencies) > 1:
            latencies.sort(key=lambda x: x[0])  # Sort by timestamp
            latencies_diff = [latencies[i+1][0] - latencies[i][0] for i in range(len(latencies)-1)]
            jitter = sum(latencies_diff) / len(latencies_diff)  # Simplified jitter calculation
            #print(f"Jitter for {ip}: {jitter} seconds")

# Store seen sequence numbers for detecting retransmissions
seen_seq_nums = defaultdict(set)

def detect_retransmission(packet):
    src_ip = packet['src_ip']
    seq_num = packet['seq_num']
    
    # Check if this sequence number has been seen before
    if seq_num in seen_seq_nums[src_ip]:
        print(f"Retransmission detected from {src_ip} with sequence number {seq_num}")
    else:
        seen_seq_nums[src_ip].add(seq_num)

# Store the last sequence number seen for each connection
last_seq_num = defaultdict(lambda: -1)

def detect_out_of_order_packet(packet):
    src_ip = packet['src_ip']
    seq_num = packet['seq_num']
    
    # Compare the current sequence number to the last seen sequence number
    if seq_num < last_seq_num[src_ip]:
        print(f"Out-of-order packet detected from {src_ip} with sequence number {seq_num}")
    
    # Update the last seen sequence number
    last_seq_num[src_ip] = seq_num