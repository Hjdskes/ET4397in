#!/usr/bin/env python

from scapy.all import *

# See http://www.secdev.org/projects/scapy/faq.html, allows sending Scapy
# packets over the loopback interface.
conf.L3socket = L3RawSocket

src = RandIP()
loopback = "lo"
print("Using IP address", src, "on interface", loopback)

while(True):
    pkt = IP(src=src, dst="127.0.0.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=str("%f" % time.time())))
    send(pkt, iface=loopback)
    time.sleep(0.5)
