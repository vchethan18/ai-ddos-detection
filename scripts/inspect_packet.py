from scapy.all import *

def process(packet):

    packet.show()

    print("=" * 50)

sniff(prn=process, count=2)
