# Packet Sniffer

## Table of Contents
- [Project Overview](#project-overview)
  - [Project Goals](#project-goals)
  - [Key Features](#key-features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Application](#run-the-packet-sniffer-with-sudo-access)
   - [Threat Detection](#threat-detection)
- [Project Structure](#project-structure)
- [Code Structure](#code-structure)
- [Contribution](#contribution)

## Project Overview
A simple packet sniffer built using Python and Flask that captures and displays network packets for specified protocols. The application captures Ethernet frames, extracts information for IPv4, ARP, ICMP, TCP, and UDP packets, and displays the captured packets in a web interface.

## Project Goals
- Create a user-friendly web interface for network packet analysis
- Provide real-time packet capture and support for multiple filters
- Enable detailed packet inspection and analysis
- Implement network security monitoring and threat detection
- Visualize network traffic patterns and statistics
- Support packet capture export for further analysis

## Key Features

### Packet Capture and Filtering
- Capture packets for specific protocols: ICMP, TCP, UDP, and ARP
- Filter packets by source and destination IP addresses
- Filter packets by size (minimum and maximum bytes)
- Save captured packets to PCAP files for further analysis

### Real-time Network Statistics
- Display total captured packets and bytes
- Show current network throughput (bytes/second)
- Visualize protocol distribution with interactive charts
- Monitor network throughput trends over time
- Track top senders and receivers with data transfer statistics

### Security Monitoring
- Detect potential SYN flood attacks
- Identify ICMP flood attempts
- Monitor and alert on port scanning activities
- Real-time threat logging and display

### User Interface
- Clean, modern web interface for packet monitoring
- Interactive packet table with protocol-specific highlighting
- Detailed packet inspection on click
- Pagination support for large packet captures
- Real-time updates of network statistics

## Contribution
- Andrew Effendi  
- Shanni Li

## Requirements

- Linux System
- Python 3.x
- Flask
- Access to raw socket privileges (may require running with administrator/root privileges or use `sudo`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/AndrewEffendi/Packet-Sniffer.git
   cd Packet-Sniffer
   ```
2. Install the required packages:

   ```bash
   sudo pip install flask
   ```
## Usage
### Run the packet sniffer with `sudo` access:

   ```bash
   sudo python sniffer.py
   ```
### Once the application is running, open your web browser and navigate to:
```bash
http://127.0.0.1:5000/
```
### Choose filter (Optional)
- `Source IP Address`: Specify a source IP address to filter the packets. (Default: ANY)
- `Destination IP Address`: Specify a target IP address to filter the packets. (Default: ANY)
- `Packet Type`: Choose from options: `icmp`, `tcp`, `udp`, `arp`. Multiple protocols can be chosen. (Default: ALL)
- `Minimum Packet Size`: Specify the minimum packet size in bytes to filter the packets. (Default: No minimum)
- `Maximum Packet Size`: Specify the maximum packet size in bytes to filter the packets. (Default: No maximum)

### Choose PCAP Filename (Optional)
- `PCAP Filename`: Specify the name of the pcap file, without the `.pcap` extension (Default: `captured_packets`)

### Clear Input
- Click the blue `Clear Input` button to reset all input fields to their default values.

### Start The packet sniffer
- press the green `Start Sniffing` button

### View Packet Details
- after the sniffer starts running, we can click on any row to show more detail of the packets

### Stop The packet sniffer
- press the red `Stop Sniffing` button

### To Open the PCAP file
```bash
wireshark <filename>.pcap
```

## Threat Detection
### `SYN Flood`: 
Detects potential SYN flood attacks by monitoring the ratio of SYN packets to ACK packets from the same source IP. If the number of SYN packets exceeds the threshold (100) and is more than three times the number of ACK packets within a 10-second window, a SYN flood is flagged.
```bash
sudo hping3 -S -p 80 -i u10000 --count 300 8.8.8.8
```
expected output
```bash
Potential SYN flood detected from 172.20.209.83
```

### `ICMP Flood`: 
Detects potential ICMP flood attacks by monitoring ICMP Packets from the same source IP. If the number of ICMP Echo Request exceeds the threshold (100), an ICMP flood is flagged.
```bash
ping -c 200 -i 0.01 8.8.8.8
```
expected output
```bash
Potential ICMP flood detected from 172.20.209.83
```

### `Port Scanning`: 
Detects potential port scanning by monitoring SYN packets. If the number of unique destination ports from the same source IP exceeds the threshold (20 unique ports) within a 10-second window, a port scan is flagged.
```bash
sudo nmap -sS 8.8.8.8
```
expected output
```bash
Potential port scan detected from 172.20.209.83 to 8.8.8.8
```

## Project Structure
```
Packet-Sniffer/
├── sniffer.py           # Main application file
├── packet_utils.py      # Packet parsing utilities
├── unpack_utils.py      # Raw data unpacking utilities
├── pcap_utils.py        # PCAP file handling
├── threat_detection.py  # Network threat detection
├── traffic_analysis.py  # Traffic analysis and statistics
├── static/
│   ├── css/
│   │   └── styles.css
│   └── js/
│       ├── scripts.js
│       └── traffic_analysis_scripts.js
└── templates/
    └── index.html
```

## Code Structure
### Sniffer.py
- `index()`: Render the template/index.html
- `packets()`: Pass packet data, packet details, and threat logs to the Flask UI
- `start_sniffing()`: Start a new thread for sniffing using the parameters specified from the UI (protocols, IP filters, packet size filters)
- `stop_sniffing()`: Stop the thread for sniffing and clean up resources
- `sniff_packets()`: Main sniffer function, sniff packets, update packet data and detail, write to pcap file
- `update_packet_data()`: Update packet data for table overview and maintain traffic statistics
- `update_packet_detail()`: Update packet detail when table row is clicked
- `run_threat_detection_IPv4()`: Run threat detection for IPv4 packets (ICMP flood, SYN flood, port scanning)
- `get_bandwidth()`: Return current bandwidth statistics including total bytes and throughput
- `get_protocol_stats()`: Return protocol distribution statistics
- `get_top_talkers()`: Return statistics about top network talkers
- `get_throughput_data()`: Return throughput data for line chart visualization
- `main()`: Initialize and run the Flask application
### packet_utils.py
- `build_packet_info()`: build structured packet info (when click table)
- `build_IPv4_overview()`: build IPV4 packet overview (table overview)
- `build_ARP_overview()`: build ARP packet overview (table overview)
### unpack_utils.py
- `mac_format(mac_raw)`: Formats raw MAC address bytes into human-readable string format (XX:XX:XX:XX:XX:XX)
- `ipv4_format(ip_raw)`: Formats raw IP address bytes into dotted decimal format (XXX.XXX.XXX.XXX)
- `format_multi_line(data, size=80)`: Formats packet data into multiple lines for readability
- `ethernet_frame(data)`: Unpacks Ethernet frame to extract destination MAC, source MAC, protocol, and payload
- `ipv4_packet(data)`: Unpacks IPv4 packet to extract version, header length, TTL, protocol, source IP, destination IP, and payload
- `arp_packet(data)`: Unpacks ARP packet to extract hardware type, protocol type, hardware size, protocol size, opcode, and MAC/IP addresses
- `icmp_packet(data)`: Unpacks ICMP packet to extract type, code, checksum, and payload
- `tcp_segment(data)`: Unpacks TCP segment to extract source port, destination port, sequence number, acknowledgment, offset, flags, and payload
- `udp_segment(data)`: Unpacks UDP segment to extract source port, destination port, length, checksum, and payload
### pacap_utils.py
- `write_pcap_global_header()`: writes pcap header
- `write_pcap_packet()`: writes pcap packet
### threat_detection.py
- `detect_port_scanning()`: Detects potential port scanning by monitoring SYN packets. If the number of unique destination ports from the same source IP exceeds the threshold (20 unique ports) within a 10-second window, a port scan is flagged.
- `detect_syn_flood()`: Detects potential SYN flood attacks by monitoring the ratio of SYN packets to ACK packets from the same source IP. If the number of SYN packets exceeds the threshold (100) and is more than three times the number of ACK packets within a 10-second window, a SYN flood is flagged.
- `detect_icmp_flood()`: Detects potential ICMP flood attacks by monitoring ICMP Packets from the same source IP. If the number of ICMP Echo Request exceeds the threshold (100), an ICMP flood is flagged.

### traffic_analyzer.py
- `start_capture(timestamp)`: Initializes traffic capture with a starting timestamp
- `update_bandwidth_stats(packet_size, elapsed_time)`: Updates bandwidth statistics and throughput data for real-time monitoring
- `update_protocol_stats(protocol)`: Updates protocol counters for traffic distribution analysis
- `update_ip_stats(src_ip, dst_ip, packet_size)`: Updates statistics for source and destination IP addresses
- `get_bandwidth_stats(is_sniffing)`: Returns current bandwidth statistics including total bytes and throughput
- `get_protocol_stats()`: Returns protocol distribution statistics with counts and percentages
- `get_top_talkers(limit=5)`: Returns statistics about top network talkers, including bytes and packet counts
- `get_throughput_data(is_sniffing)`: Returns throughput data for real-time chart visualization
- `format_bytes(bytes)`: Formats byte values into human-readable format (B, KB, MB, GB, TB)

### static/js/scripts.js
- `fetchPackets()`: Fetch packet data, packet details, and threat logs from sniffer.py
- `renderThreatLog(threatLog)`: Display threat detection logs in the UI
- `renderTable(data, detail)`: Render the packet table with pagination support and click-to-view details
- `sortTable(column)`: Sort table data by specified column in ascending/descending order
- `showPacketDetails(details)`: Display detailed packet information in a modal window
- `closeModal()`: Close the packet details modal window
- `sendStartRequest()`: Send start request to sniffer.py with filter parameters (IP, protocols, packet size)
- `sendStopRequest()`: Send stop request to sniffer.py to end packet capture
- `toggleAllCheckboxes(selectAllCheckbox)`: Toggle all protocol checkboxes based on "Select All" state
- `prevPage()`: Navigate to previous page in packet table
- `nextPage()`: Navigate to next page in packet table
- `updatePageSelector()`: Update page selection dropdown with current pagination state
- `goToPage(page)`: Navigate to specific page in packet table
- `window.onload`: Initialize modal and start periodic packet data updates

### static/js/traffic_analysis_scripts.js
- `updateProtocolChart()`: Update protocol distribution pie chart with real-time data
  - Fetches protocol statistics from server
  - Displays protocol distribution percentages
  - Updates total packet count
  - Includes tooltips with detailed packet counts
- `updateTopTalkers()`: Update top talkers tables with real-time data
  - Displays top network senders and receivers
  - Shows IP addresses, bytes transferred, and packet counts
  - Updates both sender and receiver tables
- `UpdatethroughputChart()`: Update network throughput line chart
  - Displays real-time network throughput
  - Shows throughput trends over time
  - Handles chart initialization and updates
- `DOMContentLoaded Event`: Initialize all charts and start periodic updates
  - Sets up 1-second update intervals for all charts
  - Ensures continuous real-time data visualization



