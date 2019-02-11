/* Header File for trace.c
 * Brad Levin
 * CPE 464 Project 1 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "structs.h"
#include "checksum.h"

/*TCP and UDP port definitions*/
#define HTTP_PORT  80
#define DNS_PORT   53
#define TCP0_PORT  20
#define TCP1_PORT  21
#define POP3_PORT  110
#define SMTP_PORT  25

/*ICMP types*/
#define REQ_TYPE   0x08
#define REP_TYPE   0x00

/*Ether types*/
#define IP_TYPE    0x0800
#define ARP_TYPE  0x0806

/*IP protocols*/
#define ICMP_PROTO  0x01
#define TCP_PROTO   0x06
#define UDP_PROTO   0x11

/*ARP op codes*/
#define REQ_OP  0x0001
#define REP_OP  0x0002

/*Functions to shift from u_char arrays to numbers*/
uint16_t shift_to_16(u_char *data);
uint32_t shift_to_32(u_char *data);

/*Functions to print out headers*/
void print_stats(int pack_num, int pack_len);
void print_eth(Ethernet eth);
void print_IP(IP ip);
void print_ICMP(ICMP icmp);
void print_ARP(ARP arp);
void print_TCP(TCP tcp);
void print_UDP(UDP udp);

/*Functions to decode op codes, ports, types, and protocols*/
char *port_no(u_char *data, int protocol);
char *icmp_type(u_char data);
char *eth_type(u_char *data);
char *ip_proto(u_char data);
char *arp_op(u_char *data);

/*Functions to handle parsing through packets and filling structures*/
char *eth_handler(const u_char *data);
IP  ip_handler(const u_char *data);
void icmp_handler(const u_char *data, IP ip);
void arp_handler(const u_char *data);
void tcp_handler(const u_char *data, IP ip);
void udp_handler(const u_char *data, IP ip);

/*Function to create a pseudo header*/
TCP pseudo(IP ip, TCP tcp);

/*Function to check if correct amount of arguments*/
void args(int argc);

/*Main Function*/
int main(int argc, char *argv[]);

