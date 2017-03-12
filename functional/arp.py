#!/usr/bin/env python3

import scapy
from scapy.all import *

dump = PcapWriter("arp.pcap")

# Test the detection of spurious replies, by first sending a request and then
# two identical replies.
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
    hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.2"))
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="aa:aa:aa:aa:aa:aa", psrc="192.168.0.2",
    hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.0.1"))
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="aa:aa:aa:aa:aa:aa", psrc="192.168.0.2",
    hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.0.1"))

# Gratuitous ARP request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
    hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.1"))
# Unicast request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
    hwdst="aa:aa:aa:aa:aa:aa", pdst="192.168.0.2"))

# Gratuitous ARP reply
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
    hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.1"))
# Binding the ethernet address
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="ff:ff:ff:ff:ff:ff", psrc="192.168.0.1",
    hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.0.2"))
# Broadcasted replies
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.0.1",
    hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.0.2"))
## Not internally consistent with the Ethernet header
## TODO
## IP-to-MAC allocation that is not in the list
## TODO: this depends on the configuration file -- can we test this in a nice
## way?

