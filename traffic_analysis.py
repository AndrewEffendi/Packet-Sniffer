import time
from flask import jsonify
from flask_socketio import SocketIO, emit
import threading

chart_interval = 100

class TrafficAnalyzer:
    def __init__(self,socketio):
        self.socketio = socketio
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
        self.throughputData = [None] * chart_interval
        self.timestamps = list(range(chart_interval))
        self.running = False
        self.emission_thread = None


    def start_capture(self, timestamp):
        """Initialize capture start time"""
        self.start_time = timestamp
        self.last_bandwidth_check = time.time()

    def update_bandwidth_stats(self, packet_size, elapsed_time):
        """Update bandwidth-related statistics"""
        self.total_bytes += packet_size
        self.bytes_since_last_check += packet_size

        # sum packet size as per second
        current_second = int(elapsed_time)
        # Check if the current second exceeds the last timestamp
        if current_second > self.timestamps[-1]:
            # Create new timestamps and throughput data
            new_timestamps = list(range(self.timestamps[-1] + 1, current_second + 1))
            new_throughputData = [None] * len(new_timestamps)  # Use None instead of null

            # Extend the timestamps and throughput data
            self.timestamps.extend(new_timestamps)
            self.throughputData.extend(new_throughputData)

            # Limit the size of timestamps and throughputData to chart_interval
            if len(self.timestamps) > chart_interval:
                self.timestamps = self.timestamps[-chart_interval:]  # Keep only the last chart_interval timestamps
                self.throughputData = self.throughputData[-chart_interval:]
        # Calculate the index for the current second
        current_index = self.timestamps.index(current_second)

        # Update the packet size for that second
        if self.throughputData[current_index] is None:
            self.throughputData[current_index] = packet_size  # Initialize if None
        else:
            self.throughputData[current_index] += packet_size

        # if current_second != self.last_updated_second :
        #     # last_total_packet_sizes = self.packet_sizes_per_second
        #     self.socketio.emit('throughput_update', {'throughput': self.packet_sizes_per_second})
        #     self.packet_sizes_per_second = packet_size
        #     self.last_updated_second = current_second
        #     #return last_total_packet_sizes
        # else:
        #     self.packet_sizes_per_second += packet_size
        # #return None

    def emit_throughput_stats(self):
        """Emit throughput statistics at regular intervals"""
        while self.running:
            current_time = time.time()
            elapsed_time = int(current_time - self.start_time)
            if elapsed_time < 1:
                time.sleep(0.5)
                continue

            # Emit the finished seconds
            if elapsed_time > self.timestamps[-1]:
                new_timestamps = list(range(self.timestamps[-1] + 1, elapsed_time ))
                new_throughputData = [0] * len(new_timestamps) 
                self.timestamps.extend(new_timestamps)
                self.throughputData.extend(new_throughputData)

                # Limit the size of timestamps and throughputData to chart_interval
                if len(self.timestamps) > chart_interval:
                    self.timestamps = self.timestamps[-chart_interval:]  # Keep only the last chart_interval timestamps
                    self.throughputData = self.throughputData[-chart_interval:]

                # Emit all throughput data finished
                self.socketio.emit('throughput_update', {
                    'timestamp': self.timestamps,
                    'throughput_data': self.throughputData
                })
            else:
                # Find the index of the current elapsed time
                index = self.timestamps.index(elapsed_time)

                if elapsed_time == self.timestamps[-1]:
                    # Emit data up to the last timestamp
                    self.socketio.emit('throughput_update', {
                        'timestamp': self.timestamps[:index],
                        'throughput_data': self.throughputData[:index]
                    })
                else:
                    # Emit data up to the current elapsed time and pad with None
                    padded_throughput_data = self.throughputData[:index] + [None] * (chart_interval - len(self.throughputData[:index]))
                    self.socketio.emit('throughput_update', {
                        'timestamp': self.timestamps,
                        'throughput_data': padded_throughput_data
                    })
            time.sleep(1)  # Emit every second

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
    
    def start_emission(self):
        """Start the emission thread"""
        if not self.running:  # Only start if not already running
            self.running = True
            self.emission_thread = threading.Thread(target=self.emit_throughput_stats, daemon=True)
            self.emission_thread.start()

    def stop_emission(self):
        """Stop the emission thread"""
        if self.running:  # Only stop if it is running
            self.running = False
            if self.emission_thread is not None:
                self.emission_thread.join()  # Wait for the thread to finish