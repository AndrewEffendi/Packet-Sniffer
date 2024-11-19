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
Run the packet sniffer with the desired options:

   ```bash
   sudo python sniffer.py
   ```
## Filters (from UI)
- `Source IP Address`: Specify a source IP address to filter the packets by.
- `Destination IP Address`: Specify a source IP address to filter the packets by.
- `Packet Type`: Choose from options: `icmp`, `tcp`, `udp`, `arp`. Multiple protocols can be chosen.

## PCAP Filename (from UI)
- `PCAP Filename`: Specify the name of the pcap file, captured_packets.pcap by default

### To use PCAP file
```bash
wireshark <filename>.pcap
```

# Accessing the Web Interface
Once the application is running, open your web browser and navigate to:
```bash
http://127.0.0.1:5000/
```
You will see the captured packets displayed in real-time.

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
### unpack_utils.py
- `write_pcap_global_header()`: writes pcap header
- `write_pcap_packet()`: writes pcap packet
