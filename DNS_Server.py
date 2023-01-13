from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import socket
import mmap

PORT = 53
HOST = '0.0.0.0'
DB = r'Resources\Data.txt'


def get_inet_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('mysite.com', 80))
    ipv4 = s.getsockname()[0]
    s.close()
    return ipv4


def filter_dns(packet):
    return IP in packet and DNS in packet and packet[DNS].opcode == 0 and packet[IP].dst == get_inet_ip() and packet[DNSQR].qtype == 1 and packet[DNS].ancount == 0

def print_dns(packet):
    packet.show()

def handle_packet(packet):
    dest_ip = packet[IP].src
    name = packet[DNSQR].qname.decode()
    dest_port = packet[UDP].sport
    transID = packet[DNS].id
    IPs = search_URL(name)
    if IPs[0] == 'not found':
        IPs[0] = ask(name)
        if not isinstance(IPs[0], str):
            new_packet = IP(dst=dest_ip) / UDP(dport=dest_port, sport=53) / DNS(id=transID, qr=1, qdcount=1, rcode=IPs[0]) / DNSQR(qname=name)
            return new_packet
        write_addr(name, IPs[0])
    new_packet = IP(dst=dest_ip)/UDP(dport=dest_port, sport=53)/DNS(id=transID, qr=1, qdcount=1, ancount=1)/DNSQR(qname=name)/DNSRR(rrname=name, rdata=IPs[0], ttl=1000)
    return new_packet

def search_URL(name):
    with open(DB) as f:
        for line in f.readlines():
            if name in line:
                addresses = line.strip().split(' ')
                return addresses[1:]
    return ['not found']

def write_addr(name, ip):
    with open(DB, 'a') as f:
        f.write('\n')
        f.write('{} {}'.format(name, ip))

def ask(name):
    packet = IP(dst='8.8.8.8') / UDP(dport=53, sport=2212) / DNS(qr=0, qdcount=1) / DNSQR(qname=name)
    response = sr1(packet)
    if response[DNS].rcode != 0:
        return response[DNS].rcode
    return response[DNSRR].rdata

def main():
    while True:
        dns_packet = sniff(count=1, lfilter=filter_dns, prn=print_dns)
        response = handle_packet(dns_packet[0])
        response.show()
        send(response)

if __name__ == "__main__":
    main()

