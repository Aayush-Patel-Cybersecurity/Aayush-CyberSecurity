import pyshark
import json
from datetime import datetime
import os


class AdvancedPacketAnalyzer:
    def __init__(self, interface=None, capture_file=None):
        self.interface = interface
        self.capture_file = capture_file
        self.packets_data = []
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'top_sources': {},
            'top_destinations': {},
            'suspicious_activity': []
        }

    def analyze_packet(self, packet):
        """Detailed packet analysis"""
        packet_info = {
            'timestamp': str(packet.sniff_time),
            'length': int(packet.length),
            'protocols': []
        }

        # Add all protocol layers
        for layer in packet.layers:
            packet_info['protocols'].append(layer.layer_name)

        # IP analysis
        if hasattr(packet, 'ip'):
            packet_info['src_ip'] = packet.ip.src
            packet_info['dst_ip'] = packet.ip.dst
            packet_info['ttl'] = packet.ip.ttl

            # Update statistics
            self.stats['top_sources'][packet.ip.src] = self.stats['top_sources'].get(packet.ip.src, 0) + 1
            self.stats['top_destinations'][packet.ip.dst] = self.stats['top_destinations'].get(packet.ip.dst, 0) + 1

        # Transport layer analysis
        if hasattr(packet, 'tcp'):
            packet_info['src_port'] = packet.tcp.srcport
            packet_info['dst_port'] = packet.tcp.dstport
            packet_info['transport'] = 'TCP'

            # Check for suspicious ports
            suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389]
            if int(packet.tcp.dstport) in suspicious_ports:
                self.stats['suspicious_activity'].append({
                    'type': 'Suspicious Port Access',
                    'details': f"Connection to port {packet.tcp.dstport}",
                    'timestamp': str(packet.sniff_time),
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
                })

        elif hasattr(packet, 'udp'):
            packet_info['src_port'] = packet.udp.srcport
            packet_info['dst_port'] = packet.udp.dstport
            packet_info['transport'] = 'UDP'

        # Protocol statistics
        for protocol in packet_info['protocols']:
            self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1

        self.packets_data.append(packet_info)
        self.stats['total_packets'] += 1

    def start_analysis(self, packet_count=100):
        """Start packet analysis"""
        try:
            if self.capture_file:
                # Analyze from file
                capture = pyshark.FileCapture(self.capture_file)
                print(f"Analyzing packets from file: {self.capture_file}")
            else:
                # Live capture
                capture = pyshark.LiveCapture(interface=self.interface)
                print(f"Starting live analysis on interface: {self.interface}")

            count = 0
            for packet in capture:
                self.analyze_packet(packet)
                count += 1
                if count % 10 == 0:
                    print(f"Processed {count} packets...")

                if packet_count and count >= packet_count:
                    break

            capture.close()
            print(f"Analysis complete. Processed {count} packets.")

        except Exception as e:
            print(f"Error during analysis: {e}")

    def generate_report(self):
        """Generate analysis report"""
        report = {
            'analysis_time': datetime.now().isoformat(),
            'statistics': self.stats,
            'top_protocols': sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10],
            'top_sources': sorted(self.stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10],
            'top_destinations': sorted(self.stats['top_destinations'].items(), key=lambda x: x[1], reverse=True)[:10]
        }

        return report

    def save_report(self, filename=None):
        """Save analysis report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/packet_analysis_{timestamp}.json"

        os.makedirs(os.path.dirname(filename), exist_ok=True)

        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"Report saved to: {filename}")
        return filename

    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "=" * 60)
        print("PACKET ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Unique Protocols: {len(self.stats['protocols'])}")
        print(f"Unique Source IPs: {len(self.stats['top_sources'])}")
        print(f"Suspicious Activities: {len(self.stats['suspicious_activity'])}")

        print("\nTop Protocols:")
        for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {protocol}: {count}")

        print("\nTop Source IPs:")
        for ip, count in sorted(self.stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")

        if self.stats['suspicious_activity']:
            print("\nSuspicious Activities:")
            for activity in self.stats['suspicious_activity'][:5]:
                print(f"  {activity['type']}: {activity['details']}")


# Example usage
if __name__ == "__main__":
    analyzer = AdvancedPacketAnalyzer(interface='Wi-Fi')  # Adjust interface name
    analyzer.start_analysis(packet_count=50)
    analyzer.print_summary()
    analyzer.save_report()
