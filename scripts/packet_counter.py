from scapy.all import sniff, TCP, UDP
import time

packet_count = 0
tcp_count = 0
udp_count = 0

last_time = time.time()

def process(packet):
    global packet_count, tcp_count, udp_count, last_time

    packet_count += 1

    if TCP in packet:
        tcp_count += 1

    if UDP in packet:
        udp_count += 1

    current_time = time.time()

    if current_time - last_time >= 1:

        print(
            f"PPS={packet_count} | TCP={tcp_count} | UDP={udp_count}"
        )

        packet_count = 0
        tcp_count = 0
        udp_count = 0

        last_time = current_time

sniff(prn=process)
