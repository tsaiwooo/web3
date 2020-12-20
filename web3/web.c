#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


#define MAC_ADDRSTRLEN 2*6+5+1
void dump_ethernet(u_int32_t length, const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
void dump_ip(u_int32_t length, const u_char *content);
void dump_tcp(u_int32_t length, const u_char *content) ;
void dump_udp(u_int32_t length, const u_char *content);
char *ip_ntoa(void *i);
char *mac_ntoa(u_char *d);

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    char *file = "./fuzz-2019-11-10-8100.pcap";

    
    handle = pcap_open_offline(file,errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(1);
    }//end if

    //ethernet only
    if(pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Sorry, Ethernet only.\n");
        pcap_close(handle);
        exit(1);
    }//end if

    //start capture
    pcap_loop(handle, 2, pcap_callback, NULL);

    //free
    pcap_close(handle);
    return 0;
}


char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}//end mac_ntoa

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("No. %d\n", ++d);

    //print header
    printf("\tTime: %s.%.6d\n", timestr, header->ts.tv_usec);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);

    //dump ethernet
    dump_ethernet(header->caplen, content);

    printf("\n");
}//end pcap_callback

void dump_ethernet(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    //copy header
    strlcpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strlcpy(src_mac_addr, mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);

    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("| Destination MAC Address:                                   %17s|\n", dst_mac_addr);
    printf("| Source MAC Address:                                        %17s|\n", src_mac_addr);

    if (type < 1500)
        printf("| Length:            %5u|\n", type);
    else
        printf("| Ethernet Type:    0x%04x|\n", type);
    printf("+-------------------------+\n");

    switch (type) {
        case ETHERTYPE_ARP:
            printf("Next is ARP\n");
            break;

        case ETHERTYPE_IP:
            dump_ip(length, content);
            break;

        case ETHERTYPE_REVARP:
            printf("Next is RARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Next is IPv6\n");
            break;

        default:
            printf("Next is %#06x", type);
            break;
    }//end switch

}//end dump_ethernet


void dump_ip(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    //u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_char protocol = ip->ip_p;

    //print
    printf("Protocol: IP\n");
    printf("| Source IP Address:                 %15s|\n",  ip_ntoa(&ip->ip_src));
    printf("| Destination IP Address:            %15s|\n\n", ip_ntoa(&ip->ip_dst));

    switch (protocol) {
        case IPPROTO_UDP:
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            dump_tcp(length, content);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }//end switch
}//end dump_ip

void dump_tcp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);

    //print
    printf("Protocol: TCP\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
}//end dump_tcp

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);

    printf("Protocol: UDP\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
}//end dump_udp

char *ip_ntoa(void *i) {
    static char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, i, str, sizeof(str));

    return str;
}//end ip_ntoa