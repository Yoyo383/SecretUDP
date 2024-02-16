from scapy.all import *
from scapy.layers.inet import *


def check_udp_empty(pkt):
    """
    Checks if a UDP packet is empty.
    :param pkt: The packet.
    :type pkt: Packet
    :return: Whether the packet is empty.
    :rtype: bool
    """
    payload = bytes(pkt[UDP].payload)
    return payload == b''


def filter_packets(pkt):
    """
    A filter function for sniff. It checks if the packet is IP, UDP and if it's empty.
    :param pkt: The packet.
    :type pkt: Packet
    :return: If the packet fits the filter.
    :rtype: bool
    """
    return IP in pkt and UDP in pkt and check_udp_empty(pkt)


def packet_to_letter(pkt):
    """
    Gets the letter the packet represents.
    :param pkt: The packet.
    :type pkt: Packet
    :return: The letter.
    :rtype: str
    """
    return chr(pkt[UDP].dport)


def main():
    """
    The main function. Sniffs a packet that fits the filters, gets the letter it represents and prints it.
    :return: None.
    """
    while True:
        pkt = sniff(count=1, lfilter=filter_packets)[0]
        letter = packet_to_letter(pkt)
        print(letter, end='')


if __name__ == '__main__':
    main()
