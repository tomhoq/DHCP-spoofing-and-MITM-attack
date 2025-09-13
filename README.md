# DHCP-Spoofing and MITM Attack
A small educational project demonstrating vulnerabilities in DHCP and DNS. 
This project is intended strictly for testing and learning in isolated environments. 
Do NOT use on production or external networks.

Project Structure:

### plan.txt ------------------------
Initial plan outlining the steps of the attack and overall approach.

### walkthrough.txt -----------------
Documentation of challenges faced during implementation and solutions devised.

### dns/ ----------------------------
Configuration files to set up a DNS server for testing purposes.

### dhcp_starvation/ ----------------
Implements a DHCP starvation attack using raw sockets and randomized MAC addresses 
to exhaust the IP pool of the legitimate DHCP server.

### dhcp_server/ -------------------
A simulated DHCP server implemented in C, capable of offering a single IP address. 
Sufficient for demonstrating the attack, but not a full production DHCP server.

### alpine.iso ----------------------
Virtual machine image used as the victim environment for testing.
# How it works?

### 1. DHCP Starvation:
   The attacker first launches a DHCP starvation attack to exhaust the IP address pool of the legitimate DHCP server.

### 2. Rogue DHCP and DNS Servers:
   Once the pool is exhausted, the attacker activates a rogue DHCP server (and optionally a malicious DNS server).

### 3. Victim IP Assignment:
   When a victim device joins the network, it broadcasts a DHCP DISCOVER request. Since the legitimate DHCP server has no available IPs, it cannot respond. The rogue DHCP server responds with a DHCP OFFER, providing an IP address and specifying a DNS server under the attacker’s control.

### 4. DNS Manipulation:
   The victim accepts the rogue DHCP server’s settings (via DHCP ACK) and configures its network to use the attacker’s DNS server. This allows the attacker to manipulate DNS responses. For example, requests to facebook.com could be redirected to a locally hosted fake website, tricking the victim into entering credentials.

### 5. Credential Theft:
   By controlling DNS resolution, the attacker can capture sensitive information such as login credentials, without the victim realizing the connection has been tampered with.

