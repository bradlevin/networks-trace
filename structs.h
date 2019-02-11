#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct __attribute__((packed)) ethernet{
    u_char dest[6];
    u_char src[6];
    u_char type[2];
} Ethernet;

typedef struct __attribute__((packed)) ip{
    u_char vers;
    u_char h_len;
    u_char t_len[2];
    u_char diff;
    u_char ecn;
    u_char ttl;
    u_char pro;
    unsigned short checksum;
    u_char cksum[2];
    u_char send[4];
    u_char dest[4];
} IP;


typedef struct __attribute__((packed)) icmp{
    u_char type;
} ICMP;

typedef struct __attribute__((packed)) arp{
    u_char opcode[2];
    u_char send_mac[6];
    u_char tar_mac[6];
    u_char send_ip[4];
    u_char tar_ip[4];
} ARP;

typedef struct __attribute__((packed)) tcp{
    u_char pseudo[12];
    unsigned int checksum;
    uint16_t len;
    u_char src[2];
    u_char dest[2];
    u_char seq[4];
    u_char ackno[4];
    u_char off;
    u_char syn;
    u_char rst;
    u_char fin;
    u_char ack;
    u_char win[2];
    u_char cksum[2];
} TCP;

typedef struct __attribute__((packed)) udp{
    u_char src[2];
    u_char dest[2];
} UDP;











