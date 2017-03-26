Question 1:

You can never be certain that there is a malicious actor from the presense of
disassociation and/or deauthentication frames. However, the probability that a
malicious actor is present does increase when the amount of such frames
increases, especially when they are sent within a rather short interval.

The alert configuration rules should thus allow a configurable interval to be
set.

Question 3:

In the "Regeling gebruik van frequentieruimte zonder vergunning en zonder 
meldingsplicht 2015"[1] the following is found: "Er worden geen ontoelaatbare
storingen of belemmeringen veroorzaakt in andere uitrusting en in het
frequentiegebruik door anderen". This translates to "No impermissible
interference or obstacles shall be caused in other equipment and use of
frequency by others". The same is found in the article for networks with a
reporting requirement[2]. This thus implies that you are not allowed to willfully
interfere with a third party, not even for defensive purposes to protect your
own network from intrusion.

Offensive strategies such as deauthenticating attackers are thus prohibited
The implications for network security measures are thus that the defenders are
(at least in this aspect) "on the wrong side of the law", i.e. defenders are limited
by law in what countermeasures they may take.

[1]: https://zoek.officielebekendmakingen.nl/stcrt-2015-3750.html
[2]: http://wetten.overheid.nl/BWBR0036375/2016-12-28#Artikel8

Question 4:

For WPA, there nowadays exist attacks such as the Beck-Tews attack that allow
an adversary to inject valid malicious traffic to legitimite clients. This means
that a client receiving a broadcast or a unicast management frame from an access
point using WPA, cannot be certain that either frame was sent by the base station.
For WPA2, every legitimately connected client gets to know the GTK, which means
that every such client has the ability to inject frames into the network. A client
connected to an access point using WPA2 can thus be certain that a unicast frame
was sent by the base station, but it cannot be certain for a broadcast frame.
