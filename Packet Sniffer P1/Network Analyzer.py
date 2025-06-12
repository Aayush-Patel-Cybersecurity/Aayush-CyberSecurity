#!/usr/bin/env python3
"""
Complete Packet Sniffer in Python
Captures and analyzes network packets with detailed information
"""

import socket
import struct
import textwrap
import sys
import time
from datetime import datetime
import threading
import argparse


class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.running = False

    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            if sys.platform == "win32":
                # Windows raw socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Unix raw socket
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            print("✓ Raw socket created successfully")
            return True

        except PermissionError:
            print("❌ Permission denied. Run as administrator/root!")
            return False
        except Exception as e:
            print(f"❌ Error creating socket: {e}")
            return False

    def parse_ethernet_header(self, data):
        """Parse Ethernet header (Linux/Unix)"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = socket.ntohs(eth_header[2])

        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': eth_type,
            'data': data[14:]
        }

    def parse_ip_header(self, data):
        """Parse IP header"""
        # Unpack the first 20 bytes of IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        header_length = ihl * 4

        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])

        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'data': data[header_length:]
        }

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])

        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        offset_reserved = tcp_header[4]
        tcp_offset = (offset_reserved >> 4) * 4
        flags = tcp_header[5]

        # Parse TCP flags
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1

        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'data': data[tcp_offset:]
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])

        return {
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3],
            'data': data[8:]
        }

    def parse_icmp_header(self, data):
        """Parse ICMP header"""
        icmp_header = struct.unpack('!BBH', data[:4])

        return {
            'type': icmp_header[0],
            'code': icmp_header[1],
            'checksum': icmp_header[2],
            'data': data[4:]
        }

    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

    def format_data(self, data, length=16):
        """Format data in hex and ASCII"""
        if not data:
            return ""

        result = []
        for i in range(0, len(data), length):
            chunk = data[i:i + length]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result.append(f'{i:04x}: {hex_part:<{length * 3}} {ascii_part}')

        return '\n'.join(result)

    def analyze_packet(self, data):
        """Analyze complete packet"""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print(f"\n{'=' * 80}")
        print(f"PACKET #{self.packet_count} - {timestamp}")
        print(f"{'=' * 80}")

        # For Windows, data starts with IP header
        # For Linux, data starts with Ethernet header
        if sys.platform != "win32" and len(data) >= 14:
            # Parse Ethernet header (Linux/Unix)
            eth_info = self.parse_ethernet_header(data)
            print(f"ETHERNET HEADER:")
            print(f"  Source MAC: {eth_info['src_mac']}")
            print(f"  Dest MAC: {eth_info['dest_mac']}")
            print(f"  Type: 0x{eth_info['type']:04x}")
            data = eth_info['data']

        # Parse IP header
        if len(data) >= 20:
            ip_info = self.parse_ip_header(data)
            protocol_name = self.get_protocol_name(ip_info['protocol'])

            print(f"IP HEADER:")
            print(f"  Version: {ip_info['version']}")
            print(f"  Source IP: {ip_info['src_ip']}")
            print(f"  Dest IP: {ip_info['dest_ip']}")
            print(f"  Protocol: {protocol_name} ({ip_info['protocol']})")
            print(f"  TTL: {ip_info['ttl']}")

            # Parse transport layer
            if ip_info['protocol'] == 6:  # TCP
                if len(ip_info['data']) >= 20:
                    tcp_info = self.parse_tcp_header(ip_info['data'])
                    print(f"TCP HEADER:")
                    print(f"  Source Port: {tcp_info['src_port']}")
                    print(f"  Dest Port: {tcp_info['dest_port']}")
                    print(f"  Sequence: {tcp_info['seq_num']}")
                    print(f"  Acknowledgment: {tcp_info['ack_num']}")

                    # Show active flags
                    active_flags = [flag for flag, value in tcp_info['flags'].items() if value]
                    if active_flags:
                        print(f"  Flags: {', '.join(active_flags)}")

                    # Show payload if exists
                    if tcp_info['data'] and len(tcp_info['data']) > 0:
                        print(f"TCP PAYLOAD ({len(tcp_info['data'])} bytes):")
                        print(textwrap.indent(self.format_data(tcp_info['data'][:64]), "  "))

            elif ip_info['protocol'] == 17:  # UDP
                if len(ip_info['data']) >= 8:
                    udp_info = self.parse_udp_header(ip_info['data'])
                    print(f"UDP HEADER:")
                    print(f"  Source Port: {udp_info['src_port']}")
                    print(f"  Dest Port: {udp_info['dest_port']}")
                    print(f"  Length: {udp_info['length']}")

                    # Show payload if exists
                    if udp_info['data'] and len(udp_info['data']) > 0:
                        print(f"UDP PAYLOAD ({len(udp_info['data'])} bytes):")
                        print(textwrap.indent(self.format_data(udp_info['data'][:64]), "  "))

            elif ip_info['protocol'] == 1:  # ICMP
                if len(ip_info['data']) >= 4:
                    icmp_info = self.parse_icmp_header(ip_info['data'])
                    print(f"ICMP HEADER:")
                    print(f"  Type: {icmp_info['type']}")
                    print(f"  Code: {icmp_info['code']}")

    def start_sniffing(self, count=0):
        """Start packet sniffing"""
        if not self.create_socket():
            return

        self.running = True
        print(f"\n🔍 Starting packet capture...")
        print(f"📊 Target packets: {'Unlimited' if count == 0 else count}")
        print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🛑 Press Ctrl+C to stop\n")

        try:
            while self.running:
                # Receive packet
                data, addr = self.sock.recvfrom(65536)

                # Analyze packet
                self.analyze_packet(data)

                # Check if we've reached the target count
                if count > 0 and self.packet_count >= count:
                    break

        except KeyboardInterrupt:
            print(f"\n\n🛑 Capture stopped by user")
        except Exception as e:
            print(f"\n❌ Error during capture: {e}")
        finally:
            self.stop_sniffing()

    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
        if hasattr(self, 'sock'):
            try:
                if sys.platform == "win32":
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.sock.close()
            except:
                pass

        print(f"\n📈 CAPTURE SUMMARY:")
        print(f"   Total packets captured: {self.packet_count}")
        print(f"   Session duration: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Average rate: {self.packet_count / max(1, time.time())} packets/sec")


def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='Python Packet Sniffer')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('-i', '--interface', type=str,
                        help='Network interface to sniff (Linux/Unix only)')

    args = parser.parse_args()

    print("=" * 80)
    print("🔍 PYTHON PACKET SNIFFER")
    print("=" * 80)
    print(f"Platform: {sys.platform}")
    print(f"Python Version: {sys.version}")

    # Warning message
    print("\n⚠️  LEGAL WARNING:")
    print("   Only use this tool on networks you own or have permission to monitor!")
    print("   Unauthorized packet sniffing may violate laws and regulations.")

    # System-specific instructions
    if sys.platform == "win32":
        print("\n💻 Windows Requirements:")
        print("   - Run as Administrator")
        print("   - Windows firewall may block raw sockets")
    else:
        print("\n🐧 Linux/Unix Requirements:")
        print("   - Run as root (sudo)")
        print("   - Requires libpcap or similar packet capture library")

    # Get user confirmation
    try:
        response = input("\n❓ Do you have permission to monitor this network? (y/N): ")
        if response.lower() != 'y':
            print("Exiting...")
            return
    except KeyboardInterrupt:
        print("\nExiting...")
        return

    # Create and start sniffer
    sniffer = PacketSniffer(args.interface)

    try:
        sniffer.start_sniffing(args.count)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()