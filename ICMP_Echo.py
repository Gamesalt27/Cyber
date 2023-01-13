from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether
import logging


def main():
    packet = IP(dst="142.251.142.206", src="10.100.102.7")/ICMP()
    recieved = sr1(packet)
    recieved.show()

if __name__ == "__main__":
    main()
