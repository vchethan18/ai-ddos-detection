from scapy.all import sniff, TCP, UDP, ICMP, ARP
import time

pps = 0
tcp = 0
udp = 0
icmp = 0
arp = 0

last_time = time.time()

def process(packet):
    global pps, tcp, udp, icmp, arp, last_time

    pps += 1

    if TCP in packet:
        tcp += 1

    elif UDP in packet:
        udp += 1

    elif ICMP in packet:
        icmp += 1

    elif ARP in packet:
        arp += 1

    current = time.time()

    if current - last_time >= 1:

        print(
            f"PPS={pps} | "
            f"TCP={tcp} | "
            f"UDP={udp} | "
            f"ICMP={icmp} | "
            f"ARP={arp}"
        )

        pps = tcp = udp = icmp = arp = 0
        last_time = current

sniff(prn=process)
