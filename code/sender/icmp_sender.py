from scapy.all import IP,ICMP,send

# Implement your ICMP sender here
target = "receiver"
ip_packet = IP(dst = target, ttl = 1)

request = ICMP()

packet = ip_packet / request

send(packet)
