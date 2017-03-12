#!/usr/bin/env python3

import scapy
from scapy.all import *

dump = PcapWriter("arp.pcap")

# Gratuitous ARP request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
            hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.1"))
# Unicast request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
            hwdst="aa:aa:aa:aa:aa:aa", pdst="0.0.0.0"))

# Gratuitous ARP reply
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
        hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.1"))
# Binding the ethernet address
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="ff:ff:ff:ff:ff:ff", psrc="192.168.0.1",
        hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.0.2"))
# Broadcasted replies
dump.write(ARP(op=ARP.is_at, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
        hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.2"))
# Not internally consistent with the Ethernet header
# TODO
# IP-to-MAC allocation that is not in the list
# TODO: this depends on the configuration file -- can we test this in a nice
# way?
