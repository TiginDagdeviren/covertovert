from scapy.all import IP , ICMP , sniff
# Implement your ICMP receiver here
def receive_packet (packet) : 
    if (IP in packet and ICMP in packet and packet[IP].ttl == 1 and packet[ICMP].type == 8):
        packet.show()
if __name__ == "__main__":
    sniff(filter="icmp", prn=receive_packet)
