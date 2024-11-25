import time
from flask import jsonify

class TrafficAnalyzer:
    def __init__(self):
        self.reset_stats()

    def reset_stats(self):
        """Reset all traffic statistics"""
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

    def start_capture(self, timestamp):
        """Initialize capture start time"""
        self.start_time = timestamp
        self.last_bandwidth_check = time.time()

    def update_bandwidth_stats(self, packet_size):
        """Update bandwidth-related statistics"""
        self.total_bytes += packet_size
        self.bytes_since_last_check += packet_size

    def update_protocol_stats(self, protocol):
        """Update protocol counter"""
        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts['Other'] += 1

    def update_ip_stats(self, src_ip, dst_ip, packet_size):
        """Update IP address statistics"""
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
        """Calculate and return bandwidth statistics"""
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
            if time_diff > 0:
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
        """Get protocol distribution statistics"""
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
        """Get top talkers statistics"""
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

    @staticmethod
    def format_bytes(bytes):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} TB"
