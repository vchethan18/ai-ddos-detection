from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = packet[IP].proto

        packet_length = len(packet)

        print(f"""
Source IP      : {src_ip}
Destination IP : {dst_ip}
Protocol       : {protocol}
Packet Length  : {packet_length}
-----------------------------
""")

sniff(prn=process_packet, count=20)
