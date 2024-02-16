from scapy.all import *
from scapy.layers.inet import *

TARGET_IP = '127.0.0.1'


def send_message(msg):
    """
    Sends packets that represent the letters of the message.
    :param msg: The message.
    :type msg: str
    :return: None.
    """
    for i in msg:
        port = ord(i)
        pkt = IP(dst=TARGET_IP) / UDP(dport=port)
        send(pkt)


def main():
    """
    The main function. Gets a message from the user and sends it.
    :return: None.
    """
    msg = input('Enter message: ')
    send_message(msg)


if __name__ == '__main__':
    main()
