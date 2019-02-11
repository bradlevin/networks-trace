/* Brad Levin
 * CPE 464
 * Project 1: Packet Sniffing
 * Lab Time: noon
 */
#include "trace.h"

uint16_t shift_to_16(u_char *data){
    uint16_t num = data[0];
    num <<= 8;
    num |= data[1];
    return num;
}

uint32_t shift_to_32(u_char *data){
    uint32_t num1 = data[0];
    uint32_t num2 = data[1];
    uint32_t num3 = data[2];
    num1 <<= 24;
    num2 <<= 16;
    num3 <<= 8;
    num1 |= num2;
    num1 |= num3;
    num1 |= data[3];
    return num1;
}

void print_stats(int pack_num, int pack_len){
    printf("\nPacket number: %d  Packet Len: %d\n", pack_num, pack_len);
}

void print_eth(Ethernet eth){
    printf("\n    Ethernet Header\n");
    printf("        Dest MAC: %x:%x:%x:%x:%x:%x\n", eth.dest[0],
                                                    eth.dest[1],
                                                    eth.dest[2],
                                                    eth.dest[3],
                                                    eth.dest[4],
                                                    eth.dest[5]);
    printf("        Source MAC: %x:%x:%x:%x:%x:%x\n", eth.src[0],
                                                      eth.src[1],
                                                      eth.src[2],
                                                      eth.src[3],
                                                      eth.src[4],
                                                      eth.src[5]);
    printf("        Type: %s\n", eth_type(eth.type));
}

void print_IP(IP ip){
    printf("\n    IP Header\n");
    printf("        IP Version: %u\n", ip.vers);
    printf("        Header Len (bytes): %u\n", ip.h_len * 4);
    printf("        TOS subfields:\n");
    printf("           Diffserv bits: %u\n", ip.diff);
    printf("           ECN bits: %u\n", ip.ecn);
    printf("        TTL: %d\n", ip.ttl);
    printf("        Protocol: %s\n", ip_proto(ip.pro));
    if(ip.checksum == 0){
        printf("        Checksum: Correct (0x%04x)\n", shift_to_16(ip.cksum));
    }
    else{
        printf("        Checksum: Incorrect (0x%04x)\n", shift_to_16(ip.cksum));
    }
    printf("        Sender IP: %d.%d.%d.%d\n", ip.send[0],
                                               ip.send[1],
                                               ip.send[2],
                                               ip.send[3]);
    printf("        Dest IP: %d.%d.%d.%d\n",   ip.dest[0],
                                               ip.dest[1],
                                               ip.dest[2],
                                               ip.dest[3]);
}
void print_ICMP(ICMP icmp){
    printf("\n    ICMP Header\n");
    if(!strcmp(icmp_type(icmp.type), "No")){
        printf("        Type: %d\n", icmp.type);
    }
    else{
        printf("        Type: %s\n", icmp_type(icmp.type));
    }
} 
void print_ARP(ARP arp){
    printf("\n    ARP header\n");
    printf("        Opcode: %s\n", arp_op(arp.opcode));
    printf("        Sender MAC: %x:%x:%x:%x:%x:%x\n", arp.send_mac[0],
                                                      arp.send_mac[1],
                                                      arp.send_mac[2],
                                                      arp.send_mac[3],
                                                      arp.send_mac[4],
                                                      arp.send_mac[5]);

    printf("        Sender IP: %d.%d.%d.%d\n", arp.send_ip[0],
                                               arp.send_ip[1],
                                               arp.send_ip[2],
                                               arp.send_ip[3]);

    printf("        Target MAC: %x:%x:%x:%x:%x:%x\n", arp.tar_mac[0],
                                                      arp.tar_mac[1],
                                                      arp.tar_mac[2],
                                                      arp.tar_mac[3],
                                                      arp.tar_mac[4],
                                                      arp.tar_mac[5]);

    printf("        Target IP: %d.%d.%d.%d\n\n", arp.tar_ip[0],
                                                 arp.tar_ip[1],
                                                 arp.tar_ip[2],
                                                 arp.tar_ip[3]);
}

void print_TCP(TCP tcp){
    char *src_port = port_no(tcp.src, 0);
    char *dest_port = port_no(tcp.dest, 0);
    printf("\n    TCP Header\n");
    if(!strcmp(src_port, "No")){        
        printf("        Source Port: %d\n", shift_to_16(tcp.src));
    }
    else{
        printf("        Source Port: %s\n", src_port);
    }
    if(!strcmp(dest_port, "No")){
        printf("        Dest Port:  %d\n", shift_to_16(tcp.dest));
    }
    else{
        printf("        Dest Port:  %s\n", dest_port);
    }
    printf("        Sequence Number: %u\n", shift_to_32(tcp.seq));
    printf("        ACK Number: %u\n", shift_to_32(tcp.ackno));
    printf("        Data Offset (bytes): %d\n", tcp.off*4);
    
    if(tcp.syn == 0x01){
        printf("        SYN Flag: Yes\n");
    }
    else{
        printf("        SYN Flag: No\n");
    }
    if(tcp.rst == 0x01){
        printf("        RST Flag: Yes\n");
    }
    else{
        printf("        RST Flag: No\n");
    }
    if(tcp.fin == 0x01){
        printf("        FIN Flag: Yes\n");
    }
    else{
        printf("        FIN Flag: No\n");
    }
    if(tcp.ack == 0x01){
        printf("        ACK Flag: Yes\n");
    }
    else{
        printf("        ACK Flag: No\n");
    }
    printf("        Window Size: %d\n", shift_to_16(tcp.win));
    if(tcp.checksum == 0){
        printf("        Checksum: Correct (0x%04x)\n", shift_to_16(tcp.cksum));
    }
    else{
        printf("        Checksum: Incorrect (0x%04x)\n", shift_to_16(tcp.cksum));
    }
}


void print_UDP(UDP udp){
    printf("\n  UDP Header\n");
    char *src_port = port_no(udp.src, 1);
    char *dest_port = port_no(udp.dest, 1);
    if(!strcmp(src_port, "No")){        
        printf("        Source Port: %d\n", shift_to_16(udp.src));
    }
    else{
        printf("        Source Port: %s\n", src_port);
    }
    if(!strcmp(dest_port, "No")){
        printf("        Dest Port:  %d\n", shift_to_16(udp.dest));
    }
    else{
        printf("        Dest Port:  %s\n", dest_port);
    }
}

char *port_no(u_char* data, int protocol){
    /*TCP is 0, UDP is 1*/
    char *port;
    uint16_t num = shift_to_16(data);
    if(num == HTTP_PORT && protocol == 0){
        port = "HTTP";
    }
    else if(num == DNS_PORT){
        port = "DNS";
    }
    else if((num == TCP0_PORT || num  == TCP1_PORT) && protocol == 0){
        port = "TCP";
    }
    else if(num == POP3_PORT && protocol == 0){
        port = "POP3";
    }
    else if(num == SMTP_PORT && protocol == 0){
        port = "SMTP";
    }
    else{
        port = "No";
    }
    return port;
}

char *icmp_type(u_char data){
    char *type;
    if(data == REQ_TYPE){
        type = "Request";
    }
    else if(data == REP_TYPE){
        type = "Reply";
    }
    else{
        type = "No";
    }
    return type;
}

char *eth_type(u_char *data){
    char *type; 
    uint16_t num = shift_to_16(data);
    if(num == IP_TYPE){
        type = "IP";
    }
    else if(num == ARP_TYPE){
        type = "ARP";
    }
    else{
        type = "Unknown";
    }

    return type;
}

char *ip_proto(u_char data){
    char *protocol;
    uint8_t num = data;
    if(num == ICMP_PROTO){
        protocol = "ICMP";
    }
    else if(num == TCP_PROTO){
        protocol = "TCP";
    }
    else if(num == UDP_PROTO){
        protocol = "UDP";
    }
    else{
        protocol = "Unknown";
    }
    return protocol;
}

char *arp_op(u_char *data){
    char *type;
    uint16_t num = shift_to_16(data);
    if(num == REQ_OP){
        type = "Request";
    }
    else if(num == REP_OP){
        type = "Reply";
    }
    else{
        type = "Unknown";
    }
    return type;
}

char *eth_handler(const u_char *data){    
    Ethernet eth;    
    int bytes = 0;
    memcpy(eth.dest, data, 6);
    bytes += 6;
    memcpy(eth.src, &(data[bytes]), 6);
    bytes += 6;
    memcpy(eth.type, &(data[bytes]), 2);
    bytes += 2;
    print_eth(eth);
    return eth_type(eth.type);
}

IP  ip_handler(const u_char *data){
    IP ip;
    int bytes = 14;
    u_char header[20];
    memcpy(header, &(data[bytes]), 20);
    ip.vers = data[bytes];
    bytes += 1;
    ip.h_len = ip.vers;
    ip.vers &= 0xF0;
    ip.vers >>= 4;
    ip.h_len &= 0x0F;
    ip.diff = data[bytes];
    bytes += 1;
    ip.ecn = ip.diff;
    ip.diff &= 0xFC;
    ip.diff >>= 2;
    ip.ecn &= 0x03;
    memcpy(ip.t_len, &(data[bytes]), 2);
    bytes += 6; 
    ip.ttl = data[bytes];
    bytes += 1;
    ip.pro = data[bytes];
    bytes += 1;
    ip.checksum = in_cksum((unsigned short *) header, ip.h_len*4);
    memcpy(ip.cksum, &(data[bytes]), 2);
    bytes += 2;
    memcpy(ip.send, &(data[bytes]), 4);
    bytes += 4;
    memcpy(ip.dest, &(data[bytes]), 4);
    bytes += 4;
    print_IP(ip);
    return ip;
}

void icmp_handler(const u_char *data, IP ip){
    int bytes = ip.h_len*4 + 14;
    ICMP icmp;
    icmp.type = data[bytes];
    bytes += 1;
    print_ICMP(icmp);
}

void arp_handler(const u_char *data){
    ARP arp;
    int bytes = 14;
    bytes += 6;
    memcpy(arp.opcode, &(data[bytes]), 2);
    bytes += 2;
    memcpy(arp.send_mac, &(data[bytes]), 6);
    bytes += 6;
    memcpy(arp.send_ip, &(data[bytes]), 4);
    bytes += 4;
    memcpy(arp.tar_mac, &(data[bytes]), 6);
    bytes += 6;
    memcpy(arp.tar_ip, &(data[bytes]), 4);
    bytes += 4;
    print_ARP(arp);
}

void tcp_handler(const u_char *data, IP ip){
    TCP tcp;
    int bytes = ip.h_len*4 + 14;
    tcp = pseudo(ip, tcp);
    u_char header[tcp.len];
    memcpy(header, &(data[bytes]), tcp.len);
    u_char full_head[tcp.len + 12];
    memcpy(full_head, tcp.pseudo, 12);
    memcpy(&(full_head[12]), header, tcp.len);
    tcp.checksum = in_cksum((unsigned short *) full_head, tcp.len+12);
    memcpy(tcp.src, &(data[bytes]), 2);
    bytes += 2;
    memcpy(tcp.dest, &(data[bytes]), 2);
    bytes += 2;
    memcpy(tcp.seq, &(data[bytes]), 4);
    bytes += 4;
    memcpy(tcp.ackno, &(data[bytes]), 4);
    bytes += 4;
    tcp.off = data[bytes];
    tcp.off >>= 4;
    bytes ++;
    tcp.ack = data[bytes];
    tcp.ack &= 0x10;
    tcp.ack >>= 4;
    tcp.rst = data[bytes];
    tcp.rst &= 0x04;
    tcp.rst >>= 2;
    tcp.syn = data[bytes];
    tcp.syn &= 0x02;
    tcp.syn >>= 1;
    tcp.fin = data[bytes];
    tcp.fin &= 0x01;
    bytes ++;
    memcpy(tcp.win, &(data[bytes]), 2);
    bytes += 2;
    memcpy(tcp.cksum, &(data[bytes]), 2);
    bytes += 2;
    print_TCP(tcp);

}


void udp_handler(const u_char *data, IP ip){
    int bytes = ip.h_len*4 + 14;
    UDP udp;
    memcpy(udp.src, &(data[bytes]), 2);
    bytes += 2;
    memcpy(udp.dest, &(data[bytes]), 2);
    bytes += 2;
    print_UDP(udp);
}

TCP pseudo(IP ip, TCP tcp){
    uint16_t len;
    u_char pseudo[12];
    memcpy(pseudo, ip.send, 4);
    memcpy(&(pseudo[4]), ip.dest, 4);
    pseudo[8] = 0;
    pseudo[9] = ip.pro;
    len = shift_to_16(ip.t_len) - ip.h_len*4;
    u_char byte_0 = ((len & 0xFF00) >> 8);
    u_char byte_1 = len & 0x00FF;
    pseudo[10] = byte_0;
    pseudo[11] = byte_1;
    tcp.len = len;
    memcpy(tcp.pseudo, pseudo, 12);
    return tcp;
}

void args(int argc){
    if(argc != 2){
        perror("Not the correct amount of args");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]){
    const u_char *data;
    struct pcap_pkthdr *header;
    char errbuf;
    int test;
    int len;
    int packet = 0;
    char *eth_type;
    IP ip;
    args(argc);
    pcap_t *file = pcap_open_offline(argv[1], &errbuf);
    while(1){
        packet++;
        test = pcap_next_ex(file, &header, &data);
        if(test != 1){
            break;
        }

        len = header->len;
        print_stats(packet, len);
        eth_type = eth_handler(data);
        if(!strcmp(eth_type, "IP")){
            ip = ip_handler(data);
            if(!strcmp(ip_proto(ip.pro), "ICMP")){
                icmp_handler(data, ip);
            }
            else if(!strcmp(ip_proto(ip.pro), "TCP")){
                tcp_handler(data, ip);
            }
            else if(!strcmp(ip_proto(ip.pro), "UDP")){
                udp_handler(data, ip);
            }
        }

        else if(!strcmp(eth_type, "ARP")){
            arp_handler(data);
        }
        else{
            printf("Unknown PDU\n");
        }
    }
    pcap_close(file);
    return 0;    
}







