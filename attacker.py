from scapy.all import *
pkt = sniff(count=10, filter="ICMP")
