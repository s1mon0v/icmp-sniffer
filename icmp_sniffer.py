#!/usr/bin/python3

from scapy.all import *
import signal, sys, time 

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def data_parser(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            data = packet[ICMP].load[-4:].decode("utf-8")
            print(data, flush=True, end='')

if __name__ == '__main__':

    sniff(iface='tun0', prn=data_parser) # Change "tun0" if needed
