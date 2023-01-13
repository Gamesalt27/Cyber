from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether
import logging
import time
import threading


def main():
    packet = IP(dst="1.2.3.4")/ICMP()
    threading.Thread(target=recieveData).start()
    startTime = time.time()
    currentTime = startTime
    while currentTime < startTime + 10:
        currentTime = time.time()
        send(packet)
        time.sleep(1)
    
def recieveData():
    packets = sniff(count = 1, filter = TTL_Excedded_filter)
    for packet in packets:
        packet.show()

def TTL_Excedded_filter(packet):
    return ICMP in packet and ICMP[type] == 11

if __name__ == "__main__":
    main()
