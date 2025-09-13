#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "header.h"
#include <net/if.h>
#include <linux/if_packet.h>

#define BUFLEN 1024
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363


int get_server_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if ((ifa->ifa_addr->sa_family == AF_INET) && strcmp(ifa->ifa_name, "wlp1s0") == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
            break;
        }
    }

    freeifaddrs(ifaddr);

    if (ip[0] == '\0') {
        fprintf(stderr, "Could not find IP for interface wlp1s0\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int s;
    struct sockaddr_in server_addr, dest;
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
    dhcp->xid = 0xfea36581;
    //dhcp->xid = (uint32_t)strtoul(argv[2], NULL, 16);
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);
    dhcp->ciaddr = 0;

    // Offer this IP
    inet_pton(AF_INET, "192.168.10.101", &dhcp->yiaddr);

    inet_pton(AF_INET, server_ip, &dhcp->siaddr);

    dhcp->giaddr = 0;

    uint8_t chaddr[6];
    sscanf("32:6e:85:2b:81:b4", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",

//    sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &chaddr[0], &chaddr[1], &chaddr[2], &chaddr[3], &chaddr[4], &chaddr[5]);

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
    uint32_t lease_time = htonl(3600);
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

    print_dhcp_header(buffer, sizeof(buffer));

    if (sendto(s, buffer, sizeof(struct dhcphdr) +index, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(s);
        exit(1);
    }

    printf("DHCPOFFER sent.\n");
    close(s);
    return 0;
}

