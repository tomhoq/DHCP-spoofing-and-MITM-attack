To run the dns server dnsmasq needs to be installed.

Ubuntu:
$ sudo apt-get install dnsmasq

and set the /etc/dnsmasq.conf file to be the same as the one in this dir.

The file simply stes the address facebook.com to a specific ip in my case it is my machines ip.

Dnsmasq can also work as a dhcp server but it was not used for that purpose
