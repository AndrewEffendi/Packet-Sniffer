import unpack_utils

def build_packet_info(raw_data):
    dst_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)
    packet_info = [
        f'<strong>Ethernet Frame:</strong>',
        f'  - Destination MAC: {dst_mac}',
        f'  - Source MAC: {src_mac}',
        f'  - Protocol: {eth_proto}'
    ]
    
    if eth_proto == 0x0800:  # IPv4
        version, header_length, ttl, proto, src_ip, dst_ip, data = unpack_utils.ipv4_packet(data)
        packet_info.append(f'<strong>IPv4 Packet:</strong>')
        packet_info.append(f'    - Version: {version}')
        packet_info.append(f'    - Header Length: {header_length}')
        packet_info.append(f'    - TTL: {ttl}')
        packet_info.append(f'    - Protocol: {proto}')
        packet_info.append(f'    - Source IP: {src_ip}')
        packet_info.append(f'    - Target IP: {dst_ip}')
        
        if proto == 1:  # ICMP
            icmp_type, code, checksum, data = unpack_utils.icmp_packet(data)
            packet_info.append(f'<strong>ICMP Packet:</strong>')
            packet_info.append(f'    - Type: {icmp_type}')
            packet_info.append(f'    - Code: {code}')
            packet_info.append(f'    - Checksum: {checksum}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + unpack_utils.format_multi_line(data.hex()) + '</pre>')

        elif proto == 6:  # TCP
            src_port, dst_port, sequence, acknowledgment, offset, flags, data = unpack_utils.tcp_segment(data)
            packet_info.append(f'<strong>TCP Segment:</strong>')
            packet_info.append(f'    - Source Port: {src_port}')
            packet_info.append(f'    - Destination Port: {dst_port}')
            packet_info.append(f'    - Sequence: {sequence}')
            packet_info.append(f'    - Acknowledgment: {acknowledgment}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + unpack_utils.format_multi_line(data.hex()) + '</pre>')

        elif proto == 17:  # UDP
            src_port, dst_port, length, checksum, data = unpack_utils.udp_segment(data)
            packet_info.append(f'<strong>UDP Segment:</strong>')
            packet_info.append(f'    - Source Port: {src_port}')
            packet_info.append(f'    - Destination Port: {dst_port}')
            packet_info.append(f'    - Length: {length}')
            packet_info.append(f'    - Checksum: {checksum}')
            packet_info.append('    - Data:')
            packet_info.append('<pre>' + unpack_utils.format_multi_line(data.hex()) + '</pre>')

    elif eth_proto == 0x0806:  # ARP
        hw_type, proto_type, hw_size, proto_size, opcode, sender_mac, sender_ip, dst_mac, dst_ip, _ = unpack_utils.arp_packet(data)
        packet_info.append(f'<strong>ARP Packet:</strong>')
        packet_info.append(f'    - Hardware Type: {hw_type}')
        packet_info.append(f'    - Protocol Type: {proto_type}')
        packet_info.append(f'    - Hardware Size: {hw_size}')
        packet_info.append(f'    - Protocol Size: {proto_size}')
        packet_info.append(f'    - Opcode: {opcode}')
        packet_info.append(f'    - Sender MAC: {sender_mac}')
        packet_info.append(f'    - Sender IP: {sender_ip}')
        packet_info.append(f'    - Target MAC: {dst_mac}')
        packet_info.append(f'    - Target IP: {dst_ip}')

    return packet_info

def build_IPv4_overview(raw_data, index, formatted_elapsed_time):
    dst_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)
    version, header_length, ttl, proto, src_ip, dst_ip, data = unpack_utils.ipv4_packet(data)
    packet_overview = {}
        
    # Check protocol type
    if proto == 1:  # ICMP
        packet_overview['protocol_name'] = 'ICMP'
    elif proto == 6:  # TCP
        packet_overview['protocol_name'] = 'TCP'
    elif proto == 17:  # UDP
        packet_overview['protocol_name'] = 'UDP'
    
    packet_overview['source'] = src_ip
    packet_overview['destination'] = dst_ip
    packet_overview['elapsed_time'] = formatted_elapsed_time 
    packet_overview['index'] = index

    return packet_overview

def build_ARP_overview(raw_data, index, formatted_elapsed_time):
    dst_mac, src_mac, eth_proto, data = unpack_utils.ethernet_frame(raw_data)
    packet_overview = {}

    packet_overview['protocol_name'] = 'ARP'
    packet_overview['source'] = src_mac
    # Check if the destination MAC address is a broadcast address
    if dst_mac == 'ff:ff:ff:ff:ff:ff':
        packet_overview['destination'] = f"{dst_mac} (Broadcast)"
    else:
        packet_overview['destination'] = dst_mac
    packet_overview['elapsed_time'] = formatted_elapsed_time 
    packet_overview['index'] = index

    return packet_overview

