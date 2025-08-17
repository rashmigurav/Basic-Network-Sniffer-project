# Import the necessary modules from Scapy
from scapy.all import *

def process_packet(packet):
    """
    This function is called for each captured packet.
    It analyzes the packet and prints its details.
    """
    # --- Ethernet Layer (Layer 2) ---
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        src_mac = eth_layer.src
        dst_mac = eth_layer.dst
        print(f"\n[+] Ethernet Frame: {src_mac} -> {dst_mac}")

    # --- IP Layer (Layer 3) ---
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto # This gives a number, e.g., 6 for TCP, 17 for UDP
        
        # We will use the number to get the protocol name later
        print(f"    [+] IP Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        # --- Transport Layer (Layer 4) ---
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            print(f"        [+] TCP Segment: Port {src_port} -> {dst_port}")
            
            # --- Application Layer (Payload) ---
            if packet.haslayer(Raw):
                payload = packet.getlayer(Raw).load
                print(f"            [+] Payload (Raw Data):\n---")
                # We try to decode it, but if it's not text, we just print the raw bytes
                try:
                    print(payload.decode('utf-8', errors='ignore'))
                except:
                    print(payload)
                print("---")


        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(f"        [+] UDP Datagram: Port {src_port} -> {dst_port}")
            
            # --- Application Layer (Payload) ---
            if packet.haslayer(Raw):
                payload = packet.getlayer(Raw).load
                print(f"            [+] Payload (Raw Data):\n---")
                try:
                    print(payload.decode('utf-8', errors='ignore'))
                except:
                    print(payload)
                print("---")


        elif packet.haslayer(ICMP):
            print("        [+] ICMP Packet Detected")

def sniff_packets(interface=None):
    """
    Starts the sniffing process on a given network interface.
    """
    if interface:
        print(f"[*] Starting sniffer on interface {interface}...")
        sniff(iface=interface, store=False, prn=process_packet)
    else:
        print("[*] Starting sniffer on default interface...")
        # iface=None tells Scapy to use the default interface
        # store=False tells Scapy not to store packets in memory (good for long captures)
        # prn=process_packet is the key: it tells Scapy to run our function for every packet
        sniff(store=False, prn=process_packet)

if __name__ == "__main__":
    # You can specify an interface, e.g., sniff_packets("eth0") or sniff_packets("Wi-Fi")
    # If you leave it blank, it will use the default.
    sniff_packets()