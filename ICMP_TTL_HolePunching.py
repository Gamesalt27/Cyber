from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether
import logging
import time
import threading


def main():
    packet = IP(dst="67.20.113.136", ttl=11)/ICMP()
    for i in range(0, 19):
        send(packet)
        time.sleep(0.1)


def recieveData():
    packets = sniff(count=1, filter=TTL_Excedded_filter)
    for packet in packets:
        packet.show()


def TTL_Excedded_filter(packet):
    return ICMP in packet and ICMP[type] == 11


if __name__ == "__main__":
    main()
