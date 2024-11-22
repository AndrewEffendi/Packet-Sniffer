# Packet Sniffer

A simple packet sniffer built using Python and Flask that captures and displays network packets for specified protocols. The application captures Ethernet frames, extracts information for IPv4, ARP, ICMP, TCP, and UDP packets, and displays the captured packets in a web interface.

## Features

- Capture packets for specific protocols: ICMP, TCP, UDP, and ARP.
- Filter packets by source IP address.
- Real-time display of captured packets in a web interface.
- Structured output for easy readability.

## Requirements

- Python 3.x
- Flask
- Access to raw socket privileges (may require running with administrator/root privileges or use `sudo`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/AndrewEffendi/concept58.git
   cd concept58
   ```
2. Install the required packages:

   ```bash
   pip install flask
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

### Choose PCAP Filename (Optional)
- `PCAP Filename`: Specify the name of the pcap file, without the `.pcap` extension (Default: `captured_packets`)

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

## Code Structure
### Sniffer.py
- `index()`: render the template/index.html
- `packets()`: pass packet data and packet details to the flask UI
- `start_sniffing()`: start a new thread for sniffing using the parameter specified from the UI
- `stop_sniffing()`: stop the thread for sniffing
- `sniff_packets()`: main sniffer function, sniff packet, update packet data and detail, write to pcap file
- `update_packet_data()`: to update packet data (table overview)
- `update_packet_detail()`: to update packet detail (when click table)
### packet_utils.py
- `build_packet_info()`: build structured packet info (when click table)
- `build_IPv4_overview()`: build IPV4 packet overview (table overview)
- `build_ARP_overview()`: build ARP packet overview (table overview)
### unpack_utils.py
- `mac_format()`: formats raw MAC address
- `ipv4_format()`: formats raw IP address
- `format_multi_line()`: formats data in packets
- `ipv4_packet()`: unpacks ipv4 packets
- `arp_packet()`: unpacks arp packets
- `icmp_packet()`: unpacks arp packets
- `tcp_segment()`: unpacks tcp segments
- `udp_segment()`: unpacks udp segments
### pacap_utils.py
- `write_pcap_global_header()`: writes pcap header
- `write_pcap_packet()`: writes pcap packet
### threat_detection.py
- `detect_port_scanning()`: Detects potential port scanning by monitoring SYN packets. If the number of unique destination ports from the same source IP exceeds the threshold (20 unique ports) within a 10-second window, a port scan is flagged.
- `detect_syn_flood()`: Detects potential SYN flood attacks by monitoring the ratio of SYN packets to ACK packets from the same source IP. If the number of SYN packets exceeds the threshold (100) and is more than three times the number of ACK packets within a 10-second window, a SYN flood is flagged.
- `detect_icmp_flood()`: Detects potential ICMP flood attacks by monitoring ICMP Packets from the same source IP. If the number of ICMP Echo Request exceeds the threshold (100), an ICMP flood is flagged.

### static/js/scripts.js
- `fetchPackets()`: fetch packet data and detail from sniffer.py
- `renderTable()`: renders the table (overview) with packet data, and when is clicked, show packet detail 
- `sortTable()`: sorts table when header is clicked
- `sendStartRequest()`: sends start request to sniffer.py and pass all filter variables
- `sendStopRequest()`: send stop request to sniffer.py