import time
from flask import jsonify

chart_interval = 100

"""
Traffic Analysis Module for Network Packet Sniffer

This module provides real-time traffic analysis capabilities including:
- Bandwidth monitoring and throughput calculation
- Protocol distribution statistics
- Top talkers identification
- Network throughput visualization data

The TrafficAnalyzer class maintains various statistics about network traffic
and provides methods to update and retrieve these statistics in real-time.
"""

class TrafficAnalyzer:
    """
    A class to analyze and track network traffic statistics.
    
    Maintains running statistics about:
    - Total bytes transferred
    - Current throughput
    - Protocol distribution
    - IP-based statistics
    - Real-time throughput data for visualization
    
    Attributes:
        total_bytes (int): Total bytes captured
        start_time (float): Capture start timestamp
        protocol_counts (dict): Counter for each protocol type
        ip_stats (dict): Statistics for sender and receiver IPs
        throughputData (list): Throughput data points for visualization
        timestamps (list): Timestamps for throughput data points
    """

    def __init__(self):
        """Initialize traffic analyzer with empty statistics."""
        self.reset_stats()

    def reset_stats(self):
        """
        Reset all traffic statistics to initial state.
        Called at initialization and when starting new capture.
        """
        self.total_bytes = 0
        self.start_time = -1
        self.last_bandwidth_check = None
        self.bytes_since_last_check = 0
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'Other': 0
        }
        self.ip_stats = {
            'senders': {},    # {ip: {'bytes': 0, 'packets': 0}}
            'receivers': {}   # {ip: {'bytes': 0, 'packets': 0}}
        }
        self.throughputData = []
        self.timestamps = []

    def start_capture(self, timestamp):
        """
        Initialize capture start time and reset bandwidth check timer.
        """
        self.start_time = timestamp
        self.last_bandwidth_check = time.time()

    def update_bandwidth_stats(self, packet_size, elapsed_time):
        """
        Update bandwidth statistics with new packet data.
        
        Args:
            packet_size (int): Size of the captured packet in bytes
            elapsed_time (float): Time elapsed since capture start
            
        Updates:
            - Total bytes
            - Per-second throughput data
            - Running bandwidth calculations
        """
        self.total_bytes += packet_size
        self.bytes_since_last_check += packet_size

        # sum packet size as per second
        packet_second = int(elapsed_time)

        while len(self.throughputData) <= packet_second:
            self.throughputData.append(None)
            self.timestamps.append(len(self.timestamps))  

        if self.throughputData[packet_second]:
            self.throughputData[packet_second] += packet_size
        else:
            self.throughputData[packet_second] = packet_size

    def update_protocol_stats(self, protocol):
        """
        Update protocol distribution counter.
        
        Args:
            protocol (str): Protocol name (TCP, UDP, ICMP, ARP, Other)
        """
        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts['Other'] += 1

    def update_ip_stats(self, src_ip, dst_ip, packet_size):
        """
        Update statistics for source and destination IP addresses.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            packet_size (int): Size of the packet in bytes
        """
        # Skip localhost addresses
        if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
            return

        # Update sender stats
        if src_ip not in self.ip_stats['senders']:
            self.ip_stats['senders'][src_ip] = {'bytes': 0, 'packets': 0}
        self.ip_stats['senders'][src_ip]['bytes'] += packet_size
        self.ip_stats['senders'][src_ip]['packets'] += 1

        # Update receiver stats
        if dst_ip not in self.ip_stats['receivers']:
            self.ip_stats['receivers'][dst_ip] = {'bytes': 0, 'packets': 0}
        self.ip_stats['receivers'][dst_ip]['bytes'] += packet_size
        self.ip_stats['receivers'][dst_ip]['packets'] += 1

    def get_bandwidth_stats(self, is_sniffing):
        """
        Calculate and return current bandwidth statistics.
        
        Args:
            is_sniffing (bool): Whether packet capture is currently active
        """
        current_time = time.time()
        
        if not is_sniffing or self.start_time == -1:
            return {
                "total_bytes": self.total_bytes,
                "throughput": 0,
                "formatted_total": self.format_bytes(self.total_bytes),
                "formatted_throughput": "0 B/s"
            }
        
        if self.last_bandwidth_check is None:
            throughput = 0
            self.last_bandwidth_check = current_time
        else:
            time_diff = current_time - self.last_bandwidth_check
            # use >=1 to increase the accuracy of average throughput per second
            if time_diff >= 1:  
                throughput = self.bytes_since_last_check / time_diff
                self.bytes_since_last_check = 0
                self.last_bandwidth_check = current_time
            else:
                throughput = 0
        
        return {
            "total_bytes": self.total_bytes,
            "throughput": throughput,
            "formatted_total": self.format_bytes(self.total_bytes),
            "formatted_throughput": f"{self.format_bytes(throughput)}/s"
        }

    def get_protocol_stats(self):
        """
        Get protocol distribution statistics.
        """
        total = sum(self.protocol_counts.values())
        if total == 0:
            percentages = {proto: 0 for proto in self.protocol_counts}
        else:
            percentages = {proto: (count/total)*100 
                         for proto, count in self.protocol_counts.items()}
        
        return {
            'counts': self.protocol_counts,
            'percentages': percentages,
            'total_packets': total
        }

    def get_top_talkers(self, limit=5):
        """
        Get statistics about top network talkers.
        
        Args:
            limit (int): Number of top talkers to return (default: 5)
            
        Returns:
            dict: Top senders and receivers with their statistics
        """
        def get_top_ips(ip_dict):
            sorted_ips = sorted(ip_dict.items(), 
                              key=lambda x: x[1]['bytes'], 
                              reverse=True)[:limit]
            return [{
                'ip': ip,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'formatted_bytes': self.format_bytes(stats['bytes'])
            } for ip, stats in sorted_ips]

        return {
            'top_senders': get_top_ips(self.ip_stats['senders']),
            'top_receivers': get_top_ips(self.ip_stats['receivers'])
        }
    
    def get_throughput_data(self, is_sniffing):
        """
        Get throughput data for visualization.
        
        Args:
            is_sniffing (bool): Whether packet capture is currently active
        """
        # process the data so that 0 for no packets for previous time, and none for future time

        if self.start_time == -1:
            return {
                'throughput_data': [],
                'timestamp': []
            }
        
        if not is_sniffing:
            return {
            'throughput_data': 'not_sniffing',
            'timestamp': 'not_sniffing'
        }

        current_second = int(time.time()-self.start_time)

        while len(self.throughputData) <= current_second-1:
            self.throughputData.append(0)
            self.timestamps.append(len(self.timestamps))  

        # subtitue previous array to 0, only need to check part of elments since this will be triggered every second
        for i in range(current_second-1, max(-1,current_second-11), -1):
            if self.throughputData[i] is None:
                self.throughputData[i] = 0

        if len(self.throughputData) < chart_interval:
            temp_data = self.throughputData
            temp_timestamps = self.timestamps
            addition_length = chart_interval - len(temp_data)

            for i in range(len(temp_timestamps), chart_interval):
                temp_timestamps.append(i)

            for _ in range(addition_length):
                temp_data.append(None)

            return {
            'throughput_data': temp_data,
            'timestamp': temp_timestamps
            }
        
        else:
            return {
                'throughput_data': self.throughputData[-chart_interval:],
                'timestamp': self.timestamps[-chart_interval:]
            }

    @staticmethod
    def format_bytes(bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"