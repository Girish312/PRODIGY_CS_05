from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        payload = bytes(packet[IP].payload)
        protocol = ''
        if proto == 6:
            protocol = 'TCP'
        elif proto == 17:
            protocol = 'UDP'
        else:
            protocol = 'Other'

        print(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")
        print(f"Payload: {payload[:30]}...")

def start_sniffing(interface=None):
    sniff(prn=packet_callback, iface=interface, store=False)

if __name__ == "__main__":
    start_sniffing(interface='Wi-Fi')