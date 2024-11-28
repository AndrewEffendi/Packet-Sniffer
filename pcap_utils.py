import struct

def write_pcap_global_header(file):
     """
    Writes the global header for a PCAP file to the given file object.
    """
    global_header = struct.pack(
        'IHHIIII',
        0xa1b2c3d4,  # Magic number
        2,           # Version major
        4,           # Version minor
        0,           # GMT to local correction
        0,           # Accuracy of timestamps
        65535,       # Max length of captured packets
        1            # Data link type (Ethernet)
    )
    file.write(global_header)

def write_pcap_packet(file, timestamp, captured_data):
    """
    Writes a packet with its timestamp and captured data to a PCAP file.
    """
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1e6)
    packet_len = len(captured_data)
    
    packet_header = struct.pack(
        'IIII',
        ts_sec,      # Timestamp seconds
        ts_usec,     # Timestamp microseconds
        packet_len,  # Captured length
        packet_len   # Original length
    )
    file.write(packet_header)
    file.write(captured_data)