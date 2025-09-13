dhcp_listener.sh-----
I used this initially because I could not get pcap to work properly.
In the end I was able to listen to traffic from different interfaces using raw sockets so I stopped using this

send-offer.c----
Used by dhcp listener at first but not used now

server.c--------
Code to run a dhcp server capable of sending an offer to a static ip which is enough for the required challenge
