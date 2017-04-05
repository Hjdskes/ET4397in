## Question 1

I assume that the question is meant to measure the amount of (half-open)
connections host B can have, as measuring the size of the TCB of one connection
seems to be of little value and is (as far as I know) impossible without knowing
the total size of the hash table within which the TCBs are stored. The size of
this hash table is not exposed over the wire and hence, determining the size of
a single TCB is impossible. This question is thus answered under the assumption
that the number of possible (half-open) connections is the goal.

Host A is a laptop using Scapy to send packets with random IP addresses to host
B. The following script is used:

```python
#!/usr/bin/env python

from scapy.all import *

dst = "192.168.0.44"

while(True):
    src = RandIP()
    ip=IP(src=src, dst=dst)
    syn=TCP(dport=80,flags='S',sport=80)
    send(ip/syn, verbose=0)
```

Host B is a laptop with 1GB RAM running Debian Linux with Apache/2.4.10, with
the local IP address 192.168.0.44. Naturally if you want to test this script,
you'll have to replace this IP address. SYN cookies were disabled with `sysctl
-w net.ipv4.tcp_syncookies=0`. Both laptops were connected to each other only
through a single Ethernet cable, such that the SYNACKs sent by host B were
routed to host A. I attempted to do this through the regular home network by
setting host A as the default route but this turned out to be unreliable: host A
would see some of the packets, but not all. By doing it this way, no iptables or
other configuration was required.  Prevous attempts to use iptables on host B to
redirect the SYNACKs to host A did not work, as these packets are generated in
the kernel and thus aren't routed through iptables, I think.

On host A, Wireshark was used to watch the packet flow to see when host B
stopped sending SYNACKs back to host A. Simply counting the amount of
SYNACKs then gives the number of connections host B can make.

To determine after which time a half-open connection is released by host B, the
script was not stopped after depleting host B: as soon as host B releases one
connection, a new SYNACK will arrive. The difference in time between receiving
this new SYNACK and the previous will then (roughly) give the amount of time
after which host B releases a (half-open) connection.

The experiment was repeated four times. Host B was restarted in between to
ensure a clean state. In all experiments, host B stopped sending SYNACKs after
97 (half-open) connections had been opened and released a half-open connection
after ~54 seconds.

## Question 2

The DoS module can inspect layer three and can thus see source and destination
IP addresses. It also inspects layer four and can thus see the connection state
(SYN, SYN+ACK and ACK). Therefore, it can know which hosts (belonging to IP
source addresses) are in which stage of the connection. When it sees a TCP
package with _only_ the ACK flag, the source IP address of that host is added to
a table of hosts with an established connection. Before rate limiting a packet,
it is verified that its source IP address is not in this table. Roughly this
looks as follows:

```
if SYN and not ACK:
	if table[source IP] != connected and over threshold:
		forward with a chance of 1/100, or send a RST and drop it
else if ACK and not SYN:
	table[source IP] = connected
```

This is enough to track which connections/hosts are legitimate and which are
not. Duplicating the state tracking that the OS is doing is therefore not
required.

This is implemented in module/dosmodule.go. As required, each module now sends
its decision on whether this packet is malicious or not back to main.go. When a
single module decides a packet is malicious, it is not forwarded to the actual
webserver. For configuration options, please see the README.

Rate limiting and sending resets to attacking hosts it not enough to thwart off
the attack; it merely prolongs the period for which the host remains up.
Eventually enough SYNs will reach the host to deplete its resources.
Furthermore, if there is a botnet that can afford to finish the handshake, it
can still DoS the host by generating enoug legimitate connections.

## Question 3

This approach is effective against threats of those applications that are
covered, e.g. you need an implementation for every layer 7 application out there
(HTTP, e-mail, et cetera). The HTTP example is also only effective against
attacking hosts that do not implement a complete HTTP stack; in case the botnet
exists of actual desktop computers or other devices with a complete HTTP stack
this defense is useless. This example can be extended to any other layer 7
application: if the detection relies on incomplete implementations or other
peculiar situations, the detection is easily circumvented by using hosts that do
not show that particular peculiarity.

Layer 7-based approaches can trigger false positives. Using the given example of
the captcha, a legitimate user can enter the wrong captcha by mistake. Another
example is sending a piece of Javascript code to someone that has disabled
Javascript in their browser, or uses a browser that is not capable of using
Javascript (e.g. lynx).

## Question 4

I did not have time to implement this.

## Question 5

Since the connection information is not stored on the server anymore, the cookie
needs to contain all the information necessary to establish a valid TCP
connection. The sequence number also must be increasing to conform to the TCP
protocol.

To prevent attackers from generating valid cookies and performing an ACK flood
instead of a SYN flood, the way that SYN cookies are generated must be
unpredictable to the attacker. To do so, the encoding must use a secret that the
attacker cannot guess but that can still be used to confirm that a sequence
number was generated by the server previously.

Besides that, the sequence number needs to use information about the client
(source IP and port) to differentiate between different TCP connections. If this
is not done, an attacker can setup one valid connection and subsequently reuse
this valid cookie in a TCP hijacking attack.

This results in a situation where the SYN cookie's sequence number is generated
using a timestamp (5 bits), a maximum segment size number of 3 bits and 24 bits
for the output of a hash function over the client and server IP address, the
source and destination port and the timestamp.

I did not have time to implement this.

