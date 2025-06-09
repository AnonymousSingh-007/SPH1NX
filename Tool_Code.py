"""This file holds the code SPH1NX tool uses to sniff the network and find TCP NULL SCANS and UDP SCANS happening on the system/network.
   It uses the Scapy library to capture and analyze network packets.
"""
import logging
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
from time import time
import pyttsx3

# Initialize text-to-speech engine
engine = pyttsx3.init()
# Critical ports: top 10 vulnerable + high-priority
critical_ports = [21, 23, 445, 1433, 3306, 3389, 110, 139, 161, 2049, 22, 80, 443]
# Track packet timestamps per IP
scan_counts = defaultdict(list)
# Track last voice alert time per IP
last_alert = defaultdict(float)
# Thresholds
PACKET_THRESHOLD = 10
TIME_WINDOW = 5  # seconds
ALERT_COOLDOWN = 10  # seconds

def print_banner():
    """Print the SPH1NX banner."""
    print("""
 __    ___         _      __ __  __
/ _\  / _ \ /\  /\/ |  /\ \ \\ \/ /
\ \  / /_)// /_/ /| | /  \/ / \  /
_\ \/ ___// __  / | |/ /\  /  /  \
\__/\/    \/ /_/  |_|\_\ \/  /_/\_\
    """)

def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        filename='scan_detection.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )
    logging.info("Logging setup complete.")

def is_udp_scan(packet):
    """Check if the packet is a UDP scan."""
    if packet.haslayer(IP) and packet.haslayer(UDP):
        return True, packet[IP].src, packet[UDP].dport
    elif packet.haslayer(IP) and packet.haslayer(ICMP):
        if packet[ICMP].type == 3 and packet[ICMP].code == 3:
            return True, packet[IP].src, None
    return False, None, None

def is_null_scan(packet):
    """Check if the packet is a TCP NULL scan."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 0:
            return True, packet[IP].src, packet[TCP].dport
    return False, None, None

def handle_packet(packet):
    """Process each captured packet and check for scans."""
    is_important = False
    is_null, src_ip, port = is_null_scan(packet)
    if is_null:
        msg = f"TCP NULL SCAN detected from {src_ip} on port {port}"
        logging.info(msg)
        print(msg)
        # Track packet frequency
        scan_counts[src_ip].append(time())
        scan_counts[src_ip] = [t for t in scan_counts[src_ip] if time() - t < TIME_WINDOW]
        # Check if important (critical port or high frequency)
        if port in critical_ports or len(scan_counts[src_ip]) > PACKET_THRESHOLD:
            is_important = True

    is_udp, src_ip, port = is_udp_scan(packet)
    if is_udp:
        msg = f"UDP SCAN detected from {src_ip} on port {port if port else 'unknown'}"
        logging.info(msg)
        print(msg)
        if src_ip:  # Ensure src_ip is not None
            scan_counts[src_ip].append(time())
            scan_counts[src_ip] = [t for t in scan_counts[src_ip] if time() - t < TIME_WINDOW]
            if (port and port in critical_ports) or len(scan_counts[src_ip]) > PACKET_THRESHOLD:
                is_important = True

    # Trigger voice alert for important scans
    if is_important and src_ip and time() - last_alert[src_ip] > ALERT_COOLDOWN:
        alert_msg = f"Critical scan detected from {src_ip} on port {port if port else 'unknown'}"
        engine.say(alert_msg)
        engine.runAndWait()
        last_alert[src_ip] = time()

def main():
    """Initialize SPH1NX and start packet sniffing."""
    print_banner()
    setup_logging()
    print("Starting SPH1NX scan detector... (Run as Administrator)")
    try:
        scapy.sniff(filter="tcp or udp or icmp", prn=handle_packet, store=0)
    except PermissionError:
        print("Error: Run this script with Administrator privileges")
    except KeyboardInterrupt:
        print("Stopped SPH1NX scan detector")

if __name__ == "__main__":
    main()