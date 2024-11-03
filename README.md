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
   sudo python sniffer.py [--protocols PROTOCOLS] [--src_ip SOURCE_IP]
   ```
## Options

- `--protocols`: Specify which protocols to sniff. Options are `icmp`, `tcp`, `udp`, `arp`. Multiple protocols can be specified.
- `--src_ip`: Specify a source IP address to filter the packets by.

## Example

To capture all protocols from all source IP
```bash
sudo python sniffer.py
```

To capture all protocols and filter by a specific source IP:

```bash
sudo python sniffer.py --src_ip 192.168.1.10
```
To capture only ICMP and TCP packets:
```bash
sudo python sniffer.py --protocols icmp tcp
```

# Accessing the Web Interface
Once the application is running, open your web browser and navigate to:
```bash
http://127.0.0.1:5000/
```
You will see the captured packets displayed in real-time.

## Code Structure

- `app.py`: Contains the main application code.
- `sniff()`: The function responsible for capturing packets.
- Packet parsing functions for different protocols:
  - `ethernet_frame(data)`: Unpacks Ethernet frames.
  - `ipv4_packet(data)`: Unpacks IPv4 packets.
  - `arp_packet(data)`: Unpacks ARP packets.
  - `icmp_packet(data)`: Unpacks ICMP packets.
  - `tcp_segment(data)`: Unpacks TCP segments.
  - `udp_segment(data)`: Unpacks UDP segments.
