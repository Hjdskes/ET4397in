#!/usr/bin/env python

from scapy.all import *
import sys
import numpy

loopback = "lo"
latencies = []
count = 0

def recv(pkt):
    if not pkt[DNS]:
        return
    send_time = float(pkt[DNS].qd.qname[:-1])
    recv_time = float(pkt.time)
    latency = recv_time - send_time
    print("S:", send_time, "R:", recv_time, "L:", latency)
    latencies.append(latency)
    print("Packet received with a latency of", latency)

    global count
    count += 1
    if count == 10:
        print("10 packets received. Average latency:", sum(latencies) /
        len(latencies), "seconds, std dev:", numpy.std(latencies))
        sys.exit(0)

sniff(iface=loopback, prn=recv)

