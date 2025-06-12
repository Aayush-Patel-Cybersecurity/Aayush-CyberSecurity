import pyshark


class PacketFilter:
    def __init__(self, interface):
        self.interface = interface

    def capture_http_traffic(self, packet_count=50):
        """Capture only HTTP traffic"""
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter='port 80')

        print("Capturing HTTP traffic...")
        for packet in capture.sniff_continuously(packet_count=packet_count):
            if hasattr(packet, 'http'):
                print(
                    f"HTTP Request: {packet.http.request_method if hasattr(packet.http, 'request_method') else 'Response'}")
                if hasattr(packet, 'ip'):
                    print(f"  {packet.ip.src} -> {packet.ip.dst}")
                print("-" * 30)

    def capture_dns_traffic(self, packet_count=50):
        """Capture only DNS traffic"""
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter='port 53')

        print("Capturing DNS traffic...")
        for packet in capture.sniff_continuously(packet_count=packet_count):
            if hasattr(packet, 'dns'):
                print(f"DNS Query: {packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'Unknown'}")
                if hasattr(packet, 'ip'):
                    print(f"  {packet.ip.src} -> {packet.ip.dst}")
                print("-" * 30)

    def capture_by_ip(self, target_ip, packet_count=50):
        """Capture traffic to/from specific IP"""
        bpf_filter = f'host {target_ip}'
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=bpf_filter)

        print(f"Capturing traffic for IP: {target_ip}")
        for packet in capture.sniff_continuously(packet_count=packet_count):
            if hasattr(packet, 'ip'):
                print(f"{packet.ip.src} -> {packet.ip.dst}")
                if hasattr(packet, 'tcp'):
                    print(f"  TCP: {packet.tcp.srcport} -> {packet.tcp.dstport}")
                elif hasattr(packet, 'udp'):
                    print(f"  UDP: {packet.udp.srcport} -> {packet.udp.dstport}")
                print("-" * 30)