/*
 * header.c
 *
 *
 *      some of the code is from site BinaryTides, written by Silver Moon
 */

#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<string.h>
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>  
#include<netinet/in.h>
#include<arpa/inet.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "header.h"


void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr_1 *eth = (struct ethhdr_1 *)Buffer;

    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char * Buffer, int Size)
{
    //print_ethernet_header(Buffer , Size);

    printf("aa\n");
    struct iphdr *iph = (struct iphdr *)(Buffer );


    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));
    //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    //printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    //printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void generate_random_xid(uint32_t *xid) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    if (read(fd, xid, sizeof(*xid)) != sizeof(*xid)) {
        perror("read /dev/urandom");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Generated random xid: %u\n", *xid);

    close(fd);
}

void generate_random_mac(uint8_t *mac) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    if (read(fd, mac, 6) != 6) {
        perror("read /dev/urandom");
        close(fd);
        exit(EXIT_FAILURE);
    }

    //set the multicast bit stinn doesnt work
    //mac[0] = (mac[0] & 0xFE) | 0x02; 
    printf("Generated random MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    close(fd);

}



void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
	unsigned short ethhdr_1len = sizeof(struct ethhdr_1);

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr_1) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr_1));

    int header_size =  sizeof(struct ethhdr_1) + iphdrlen + tcph->doff*4;

    printf("\n\n***********************TCP Packet*************************\n");

    print_ip_header(Buffer,Size);

    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IP Header\n");
    PrintData(Buffer+ethhdr_1len,iphdrlen);

    printf("TCP Header\n");
    PrintData(Buffer+ethhdr_1len+iphdrlen,tcph->doff*4);

    printf("Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    printf("\n###########################################################");
}

void print_udp_packet(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer );
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen );

    printf("\n\n***********************UDP Packet*************************\n");

    //print_ip_header(Buffer,Size);

    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    printf("\n");
    //printf("IP Header\n");
    //PrintData(Buffer , iphdrlen);

    //printf("UDP Header\n");
    //PrintData(Buffer+iphdrlen , sizeof udph);

    //printf("Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , Size - header_size);

    printf("\n###########################################################");
}

void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;
	unsigned short ethhdr_1len = sizeof(struct ethhdr_1);

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr_1));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr_1));

    int header_size =  sizeof(struct ethhdr_1) + iphdrlen + sizeof icmph;

    printf("\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    printf("\n");

    printf("ICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
    {
        printf("  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        printf("  (ICMP Echo Reply)\n");
    }

    printf("   |-Code : %d\n",(unsigned int)(icmph->code));
    printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
    //printf("   |-ID       : %d\n",ntohs(icmph->id));
    //printf("   |-Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");

    printf("IP Header\n");
    PrintData(Buffer+ethhdr_1len,iphdrlen);

    printf("UDP Header\n");
    PrintData(Buffer+ethhdr_1len + iphdrlen , sizeof icmph);

    printf("Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );

    printf("\n###########################################################");
}

void print_dhcp_header (const u_char * Buffer , int Size)
{
    struct dhcphdr *dhcp = (struct dhcphdr *)(Buffer);

    printf("\n");
    unsigned char *options = (unsigned char *)dhcp->options;
    printf("\n\n***********************DHCP Packet*************************\n");
    printf("DHCP Header\n");
    printf("   |-Operation Code : %d\n",dhcp->op);
    printf("   |-Hardware Type  : %d\n",dhcp->htype);
    printf("   |-Hardware Length: %d\n",dhcp->hlen);
    printf("   |-Hops           : %d\n",dhcp->hops);
    printf("   |-Transaction ID : %u\n",ntohl(dhcp->xid));
    printf("   |-Seconds        : %d\n",ntohs(dhcp->secs));
    printf("   |-Flags          : %d\n",ntohs(dhcp->flags));
    printf("   |-Client IP      : %s\n",inet_ntoa(*(struct in_addr *)&dhcp->ciaddr));
    printf("   |-Your IP        : %s\n",inet_ntoa(*(struct in_addr *)&dhcp->yiaddr));
    printf("   |-Server IP      : %s\n",inet_ntoa(*(struct in_addr *)&dhcp->siaddr));
    printf("   |-Gateway IP     : %s\n",inet_ntoa(*(struct in_addr *)&dhcp->giaddr));
    printf("   |-Client MAC     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", dhcp->chaddr[0] , dhcp->chaddr[1] , dhcp->chaddr[2] , dhcp->chaddr[3] , dhcp->chaddr[4] , dhcp->chaddr[5]);
    //printf("   |-Server Hostname: %s\n" , dhcp->sname);
    //printf("   |-Boot Filename  : %s\n" , dhcp->file);
    //printf("   |-Magic Cookie  : %x\n" , ntohl(dhcp->magic));
        printf("\n");
        printf("   |-DHCP Magic Cookie: %x\n", ntohl(dhcp->magic));
        printf("   |-DHCP Options: ");
        int i = 0;
        while (i < (Size - sizeof(struct iphdr) - sizeof(struct udphdr) - sizeof(struct dhcphdr))) {
            uint8_t code = options[i];
            if (code == 255) {
                printf("\tOption: 255 (End)\n");
                break;
            } else if (code == 0) {
                printf("\tOption: 0 (Padding)\n");
                i++;
                continue;
            }

            uint8_t len = options[i + 1];
            printf("\tOption: %d, Length: %d, Value: ", code, len);
            for (int j = 0; j < len; j++) {
                printf("%02X ", options[i + 2 + j]);
            }
            printf("\n");

            i += 2 + len;
        }

    printf("**********************************************************\n");
}

void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }

        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              printf("   "); //extra spaces
            }

            printf("         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }

            printf( "\n" );
        }
    }
}

unsigned short checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

