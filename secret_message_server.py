from scapy.all import *
from scapy.layers.inet import *


def check_udp_empty(pkt):
    payload = bytes(pkt[UDP].payload)
    return payload == b''


def filter_packets(pkt):
    return IP in pkt and UDP in pkt and check_udp_empty(pkt)


def main():
    while True:
        pkt = sniff(count=1, lfilter=filter_packets)
        letter = chr(pkt[UDP].dport)
        print(letter)


if __name__ == '__main__':
    main()