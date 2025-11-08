
from scapy.all import sniff, IP, TCP, UDP

def packet_handler(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n--- Packet Captured ---")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            if packet.payload:
                print(f"Payload Data: {bytes(packet.payload)}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            if packet.payload:
                print(f"Payload Data: {bytes(packet.payload)}")

def main():
    print("Network Packet Analyzer started. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
