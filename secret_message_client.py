from scapy.all import *
from scapy.layers.inet import *

TARGET_IP = '127.0.0.1'


def send_message(msg: str):
    for i in msg:
        port = ord(i)
        pkt = IP(dst=TARGET_IP) / UDP(dport=port)
        send(pkt)


def main():
    msg = input('enter message: ')
    send_message(msg)


if __name__ == '__main__':
    main()
