#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <time.h>
#include <ifaddrs.h>
#include "header.h"

#define TYPE_DISCOVER 1
#define TYPE_REQUEST 3
#define DHCP_MAGIC_COOKIE 0x63825363
#define SRC_IP  "0.0.0.0"
#define DHCP_CLIENT_PORT 68
#define DEST_IP "255.255.255.255"
#define DHCP_SERVER_PORT 67
#define IP_TO_OFFER "10.30.103.100" // change 
#define ROUTER_IP "10.30.5.1" //Change
#define LEASE_TIME 3600 // 1 hour
int BROADCAST_IP[4] = {10, 30, 15, 255}; // change
int DNS_IP[4] = {192, 168, 1, 1}; // change
int SUBNET_MASK[4] = {255, 255, 255, 0}; // change

uint32_t xid;
uint8_t mac[6];

int dhcp_listen(int sockd, int type);
int dhcp_send_offer();
int dhcp_ack();

char *interface;


int get_server_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if ((ifa->ifa_addr->sa_family == AF_INET) && strcmp(ifa->ifa_name, interface) == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (ip[0] == '\0') {
        fprintf(stderr, "Could not find IP for interface %s \n", interface);
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    interface = argv[1];

    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("Error creating raw socket ");
        exit(1);
    }

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    int broadcast = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_port = htons(DHCP_SERVER_PORT);


    if (dhcp_listen(fd, TYPE_DISCOVER) != 0) return -1;

    if (dhcp_send_offer() != 0) return -1;

    if (dhcp_listen(fd, TYPE_REQUEST) != 0) return -1;


    if (dhcp_ack()) return -1;
    if (dhcp_ack()) return -1;


    close(fd);
    return 0;
}


int dhcp_listen(int sockfd, int type) {
    char frame[65536];
    struct sockaddr_ll sender;
    socklen_t sender_len = sizeof(sender);
    struct ethhdr_1 *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    struct dhcphdr *dhcp;

    while (1) {
        printf("Waiting for DHCPOFFER...\n");
        memset(frame, 0, sizeof(frame));
        int len = recvfrom(sockfd, frame, sizeof(frame), 0, (struct sockaddr *)&sender, &sender_len);
        if (len < 0) {
            perror("recvfrom");
            return -1;
        }

        //unsigned char *raw_dhcp = (unsigned char *)frame;
        //printf("DHCP bytes at offset:\n");
        /*
        int eight = 0;

        for (int i = 0; i < len; i++) {
            printf("%02X ", raw_dhcp[i]);
            eight++;
            if (eight == 8) {
                printf("  ");
            } else if (eight == 16) {
                printf("\n");
                eight = 0;
            }
        }*/

        //printf("Received packet of length %d\n", len);

//        print_ethernet_header(frame, len);

        eth = (struct ethhdr_1 *)frame;
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            //printf("Not an IP packet\n");
            //printf("%d vs %d\n", ntohs(eth->h_proto), ETH_P_IP);
            continue;
        } ; // Not an IP packet
        iph = (struct iphdr *)(frame + sizeof(struct ethhdr_1));
        //print_ip_header(frame+sizeof(struct ethhdr_1), len);
        if ( iph->protocol != IPPROTO_UDP) {
            //printf("Not a UDP packet\n");
            //printf("%d vs %d\n", iph->protocol, IPPROTO_UDP);
            continue;
        };

        udph = (struct udphdr *)(frame +  sizeof(struct ethhdr_1) + iph->ihl * 4);
        //print_udp_packet(frame+sizeof(struct ethhdr_1) + iph->ihl * 4, len);
        if (ntohs(udph->dest) != DHCP_SERVER_PORT) {
            //printf("Not a DHCP packet\n");
            //printf("%d vs %d\n", ntohs(udph->dest), SRC_PORT);
            continue;
        }; 
        //printf("Received packet from %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
        dhcp = (struct dhcphdr *)(frame + sizeof(struct ethhdr_1) + iph->ihl * 4 + sizeof(struct udphdr));
        //print_dhcp_header(frame+sizeof(struct ethhdr_1) + iph->ihl * 4 + sizeof(struct udphdr), len);
        if (dhcp->op != 1 ) {
            printf("Not a DHCPDISCOBERY or REQUEST\n");

            continue; // not an offer
        }
        uint8_t *opts = dhcp->options;
        if (opts[0] == 53 && opts[2] == type) { // DHCP DISCOVERY
            if (type == TYPE_REQUEST) {
                printf("Received DHCP REQUEST:\n");
            } else {
                printf("Received DHCP DISCOVER:\n");
            }

            memcpy(mac, dhcp->chaddr, 6);
            xid = ntohl(dhcp->xid);
            printf("Mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   mac[0], mac[1], mac[2],
                   mac[3], mac[4], mac[5]);
            printf("XID: 0x%x\n", xid);
            return 0;
        }
        else {
            printf("Not a DHCP DISCOVER or REQUEST\n");
        }
    }

    return -1;
}

int dhcp_send_offer() {
    int s;
    struct sockaddr_in dest, server_addr;
    char server_ip[INET_ADDRSTRLEN];

    if (get_server_ip(server_ip) < 0) {
        fprintf(stderr, "Failed to get server IP address\n");
        exit(1);
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        exit(1);
    }

    int broadcastEnable = 1;
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        perror("setsockopt");
        close(s);
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(s);
        exit(1);
    }

    // Build DHCP Offer
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    struct dhcphdr *dhcp = (struct dhcphdr *)buffer;

    dhcp->op = 2; // OFFER
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    //dhcp->xid = 0xfea36581;
    dhcp->xid = htonl(xid);
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);
    dhcp->ciaddr = 0;

    // Offer this IP
    inet_pton(AF_INET, IP_TO_OFFER, &dhcp->yiaddr);

    inet_pton(AF_INET, server_ip, &dhcp->siaddr);

    dhcp->giaddr = 0;

    uint8_t chaddr[6];
    //sscanf("32:6e:85:2b:81:b4", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    memcpy(chaddr, mac, 6);

    memcpy(dhcp->chaddr, chaddr, 6);

    dhcp->magic = htonl(DHCP_MAGIC_COOKIE);

    // Options
    int index = 0;
    dhcp->options[index++] = 53; // DHCP Message Type
    dhcp->options[index++] = 1;
    dhcp->options[index++] = 2; // DHCPOFFER

    dhcp->options[index++] = 54; // Server Identifier
    dhcp->options[index++] = 4;
    inet_pton(AF_INET, server_ip, &dhcp->options[index]);
    index += 4;

    dhcp->options[index++] = 51; // IP address lease time
    dhcp->options[index++] = 4;
    uint32_t lease_time = htonl(LEASE_TIME);
    memcpy(&dhcp->options[index], &lease_time, 4);
    index += 4;

    dhcp->options[index++] = 1; // Subnet Mask
    dhcp->options[index++] = 4;
    dhcp->options[index++] = 255;
    dhcp->options[index++] = 255;
    dhcp->options[index++] = 255;
    dhcp->options[index++] = 0;

    dhcp->options[index++] = 3; // Router
    dhcp->options[index++] = 4;
    dhcp->options[index++] = 192;
    dhcp->options[index++] = 168;
    dhcp->options[index++] = 10;
    dhcp->options[index++] = 1;

    dhcp->options[index++] = 6; // DNS
    dhcp->options[index++] = 4;
    dhcp->options[index++] = 8;
    dhcp->options[index++] = 8;
    dhcp->options[index++] = 8;
    dhcp->options[index++] = 8;

    dhcp->options[index++] = 255; // End option

    // Destination
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_CLIENT_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    //print_dhcp_header(buffer, sizeof(buffer));

    if (sendto(s, buffer, sizeof(struct dhcphdr) +index, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(s);
        exit(1);
    }

    printf("DHCPOFFER sent.\n");
    close(s);
    return 0;
}

int dhcp_ack() {
    int s;
    struct sockaddr_in dest, server_addr;
    char server_ip_str[INET_ADDRSTRLEN];

    // Get the server's IP address
    if (get_server_ip(server_ip_str) < 0) {
        fprintf(stderr, "Failed to get server IP address\n");
        exit(1);
    }

    // Create the socket to send the DHCP ACK message
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT); // Same port used for DHCP
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(s);
        exit(1);
    }

    // Build the DHCP ACK message
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    struct dhcphdr *dhcp = (struct dhcphdr *)buffer;

    dhcp->op = 2; 
    dhcp->htype = 1; 
    dhcp->hlen = 6;  
    dhcp->hops = 0;
    dhcp->xid = htonl(xid); 
    dhcp->secs = 0;
    dhcp->flags = 0; 
    dhcp->ciaddr = 0; 
    inet_pton(AF_INET, IP_TO_OFFER, &dhcp->yiaddr);
    dhcp->siaddr = 0;
    dhcp->giaddr = 0; 

    memcpy(dhcp->chaddr, mac, 6);

    dhcp->magic = htonl(DHCP_MAGIC_COOKIE);

    // Options
    int index = 0;

    // DHCP Message Type: DHCP ACK
    dhcp->options[index++] = 53; // DHCP Message Type
    dhcp->options[index++] = 1;
    dhcp->options[index++] = 5; // DHCPACK

    // Server Identifier (the server IP)
    dhcp->options[index++] = 54; // Server Identifier
    dhcp->options[index++] = 4;
    inet_pton(AF_INET, server_ip_str, &dhcp->options[index]);
    index += 4;

    // Lease Time (1 hour in seconds)
    dhcp->options[index++] = 51; // IP Address Lease Time
    dhcp->options[index++] = 4;
    uint32_t lease_time = htonl(LEASE_TIME); // 1 hour lease time
    memcpy(&dhcp->options[index], &lease_time, 4);
    index += 4;

    // Subnet Mask
    dhcp->options[index++] = 1; // Subnet Mask
    dhcp->options[index++] = 4;
    dhcp->options[index++] = SUBNET_MASK[0];
    dhcp->options[index++] = SUBNET_MASK[1];
    dhcp->options[index++] = SUBNET_MASK[2];
    dhcp->options[index++] = SUBNET_MASK[3];

    // Router (default gateway)
    unsigned char router_ip[4];
    inet_pton(AF_INET, ROUTER_IP, &router_ip);
    dhcp->options[index++] = 3; // Router
    dhcp->options[index++] = 4;
    memcpy(&dhcp->options[index], router_ip, 4);
    index += 4;

    // DNS Servers
    dhcp->options[index++] = 6; // DNS
    dhcp->options[index++] = 4;
    dhcp->options[index++] = DNS_IP[0];
    dhcp->options[index++] = DNS_IP[1];
    dhcp->options[index++] = DNS_IP[2];
    dhcp->options[index++] = DNS_IP[3];

    // Broadcast address
    dhcp->options[index++] = 28; // Broadcast address
    dhcp->options[index++] = 4;
    dhcp->options[index++] = BROADCAST_IP[0];
    dhcp->options[index++] = BROADCAST_IP[1];
    dhcp->options[index++] = BROADCAST_IP[2];
    dhcp->options[index++] = BROADCAST_IP[3];

    // End option
    dhcp->options[index++] = 255;

    // Destination: send it to the client via broadcast (255.255.255.255)
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_CLIENT_PORT);
    dest.sin_addr.s_addr = dhcp->yiaddr;

    if (sendto(s, buffer, sizeof(struct dhcphdr) + index, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(s);
        exit(1);
    }

    printf("DHCP ACK sent.\n");

    // Close the socket after sending
    close(s);
    return 0;
}
