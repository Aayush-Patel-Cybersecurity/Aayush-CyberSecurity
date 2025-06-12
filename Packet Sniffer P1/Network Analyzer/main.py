from datetime import datetime

import pyshark
import sys
from colorama import init, Fore, Style

init()


class PacketSniffer:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.packet_count = 0

    def packet_handler(self, packet):
        """Handle captured packets"""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            print(f"\n{Fore.CYAN}[{self.packet_count}] {timestamp}{Style.RESET_ALL}")
            print(f"Protocol: {packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'}")

            if hasattr(packet, 'ip'):
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
                print(f"Length: {packet.ip.len}")

            if hasattr(packet, 'tcp'):
                print(f"Source Port: {packet.tcp.srcport}")
                print(f"Destination Port: {packet.tcp.dstport}")
                print(f"Flags: {packet.tcp.flags}")

            if hasattr(packet, 'udp'):
                print(f"Source Port: {packet.udp.srcport}")
                print(f"Destination Port: {packet.udp.dstport}")
                print(f"Length: {packet.udp.len}")

            print("-" * 50)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_capture(self, packet_count=None):
        """Start packet capture"""
        try:
            print(f"{Fore.GREEN}Starting packet capture on interface: {self.interface}{Style.RESET_ALL}")
            print(f"Press Ctrl+C to stop capture")

            capture = pyshark.LiveCapture(interface=self.interface, display_filter='tcp or udp')

            if packet_count:
                capture.sniff(packet_count=packet_count, callback=self.packet_handler)
            else:
                capture.sniff(callback=self.packet_handler)

        except KeyboardInterrupt :
            print(f"\n{Fore.YELLOW}Capture stopped by user{Style.RESET_ALL}")
            print(f"Total packets captured: {self.packet_count}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def main():
    print("Available Network interfaces:")
    try:
        import subprocess
        if sys.platform == "win32":
            output = subprocess.run(['tshark', '-D'], capture_output=True, text=True)
        else:
            output = subprocess.run(['tshark', '-D'], capture_output=True, text=True, shell=True)
        print(output.stdout)
    except:
        print("Could not list interfaces. Using default.")

    interface = input("Enter the interface to capture packets on(or press enter for default): ").strip()
    if not interface:
        interface = 'wifi' if sys.platform == 'win32' else 'eth0'
        sniffer = PacketSniffer(interface)
        sniffer.start_capture()

    if __name__ == "__main__":
        main()


