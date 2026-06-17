from scapy.all import sniff, IP, TCP

print("Starting capture...")

def process(packet):

    if IP in packet and TCP in packet:

        print(f"""
SRC IP  : {packet[IP].src}
DST IP  : {packet[IP].dst}

SRC PORT: {packet[TCP].sport}
DST PORT: {packet[TCP].dport}

FLAGS   : {packet[TCP].flags}
""")

sniff(prn=process, count=20)

print("Capture finished")
