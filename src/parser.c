#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/igmp.h>
#include <pcap.h>
#include "utils.h"
#include "parser.h"
#include <time.h>
#include <ctype.h>

// Protocol numbers
enum ip_protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPV6 = 58,
    IGMP = 2
};

// Function to print byte_offset
void print_packet_data(const u_char *packet, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                // Print ASCII representation for the previous line
                printf(" ");
                for (int j = i - 16; j < i; j++) {
                    if (isprint(packet[j]))
                        printf("%c", packet[j]);
                    else
                        printf(".");
                }
            }
            // Start new line and print offset
            printf("\n0x%04x:  ", i);
        }
        printf("%02x ", packet[i]);
    }
    // Print remaining ASCII characters for the last line
    int bytes_remaining = i % 16;
    int spaces_to_add = (16 - bytes_remaining) * 3; // 3 spaces per missing byte: two for the byte and one for space
    for (int k = 0; k < spaces_to_add; k++) {
        printf(" ");
    }
    printf(" ");
    int start_index = i - bytes_remaining;
    for (int j = start_index; j < i; j++) {
        if (isprint(packet[j]))
            printf("%c", packet[j]);
        else
            printf(".");
    }
    printf("\n");
}

// Additional function to prevent SIGSEGV
void mac_to_str(const unsigned char *mac, char *str, size_t size) {
    if (mac == NULL || str == NULL) return;
    snprintf(str, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to parse the Ethernet header
void parse_ethernet_header(const u_char *packet, struct timeval ts, int length) {
    char timestamp[64];
    if (!packet) {
        printf("Packet data is NULL\n");
        return;
    }
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (!eth_header) {
        printf("Ethernet header is NULL\n");
        return;
    }
    int type = ntohs(eth_header->ether_type);

    char src_mac[18], dst_mac[18];
    mac_to_str(eth_header->ether_shost, src_mac, sizeof(src_mac));
    mac_to_str(eth_header->ether_dhost, dst_mac, sizeof(dst_mac));

    time_t rawtime = ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);  
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", timeinfo);
    int milliseconds = ts.tv_usec / 1000; 

    printf("\n------------------------------------------------------------------------------\n");
    printf("timestamp: %s.%03d+02:00\n", timestamp, milliseconds);
    printf("src MAC: %s\n", src_mac);
    printf("dst MAC: %s\n", dst_mac);
    printf("frame length: %d bytes\n", length);

    if (type == ETHERTYPE_IP) {
        parse_ip_header(packet + sizeof(struct ether_header));
    } else if (type == ETHERTYPE_ARP) {
        parse_arp_header(packet + sizeof(struct ether_header));
    } else if (type == ETHERTYPE_IPV6) {
        parse_ipv6_header(packet + sizeof(struct ether_header));
    } else {
        printf("Unsupported Ethernet Type: 0x%04x\n", type);
    }
}

// Function to parse the ARP header
void parse_arp_header(const u_char *packet) {
    if (!packet) {
        printf("Error: ARP packet is NULL\n");
        return;
    }
    struct ether_arp *arp_header = (struct ether_arp *) packet;
    if (ntohs(arp_header->ea_hdr.ar_hrd) != ARPHRD_ETHER) {
        printf("Unsupported hardware type\n");
        return;
    }
    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

    char sender_mac[18], target_mac[18];
    snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    printf("ARP Operation: %s\n", (ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REQUEST) ? "Request" : "Reply");
    printf("Sender MAC: %s, Sender IP: %s\n", sender_mac, sender_ip);
    printf("Target MAC: %s, Target IP: %s\n", target_mac, target_ip);
}

// Function to parse the IP header
void parse_ip_header(const u_char *packet) {
    struct ip *ip_header = (struct ip*) packet;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("src IP: %s\n", src_ip);
    printf("dst IP: %s\n", dst_ip);

    if (ip_header->ip_p == IPPROTO_TCP) {
        parse_tcp_header(packet + ip_header->ip_hl * 4);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        parse_udp_header(packet + ip_header->ip_hl * 4);
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        parse_icmp_header(packet + ip_header->ip_hl * 4);
    } else if (ip_header->ip_p == IGMP) {
        parse_igmp_header(packet + ip_header->ip_hl * 4);
    } else {
        printf("Unsupported IP protocol: %u\n", ip_header->ip_p);
    }
}

// Function to parse the IPv6 header
void parse_ipv6_header(const u_char *packet) {
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *) packet;

    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

    printf("src IP: %s\n", src_ip);  
    printf("dst IP: %s\n", dst_ip);
    printf("IPv6 Next Header: %u\n", ipv6_header->ip6_nxt);

    switch (ipv6_header->ip6_nxt) {
        case IPPROTO_TCP:
            parse_tcp_header(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_UDP:
            parse_udp_header(packet + sizeof(struct ip6_hdr));
            break;
        case IPPROTO_ICMPV6:
            parse_icmpv6_header(packet + sizeof(struct ip6_hdr));
            break;
        default:
            printf("Unsupported IPv6 next header: %u\n", ipv6_header->ip6_nxt);
    }
}

// Function to parse the ICMPv6 header
void parse_icmpv6_header(const u_char *packet) {
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) packet;

    printf("ICMPv6 Type: %d\n", icmp6_header->icmp6_type);
    printf("ICMPv6 Code: %d\n", icmp6_header->icmp6_code);
}

// Function to parse the IGMP header
void parse_igmp_header(const u_char *packet) {
    struct igmp *igmp_header = (struct igmp *) packet;

    printf("IGMP Type: %d\n", igmp_header->igmp_type);
    printf("IGMP Max Resp Time: %d\n", igmp_header->igmp_code);
    printf("IGMP Group Address: %s\n", inet_ntoa(igmp_header->igmp_group));
}

// Function to parse the TCP header
void parse_tcp_header(const u_char *packet) {
    struct tcphdr *tcp_header = (struct tcphdr *) packet;
    printf("protocol: TCP\n");
    printf("src port: %d\n", ntohs(tcp_header->source));
    printf("dst port: %d\n", ntohs(tcp_header->dest));
}

// Funtion to parse the UDP header
void parse_udp_header(const u_char *packet) {
    struct udphdr *udp_header = (struct udphdr *) packet;
    printf("protocol: UDP\n");
    printf("src port: %d\n", ntohs(udp_header->source));
    printf("dst port: %d\n", ntohs(udp_header->dest));
}

// Function to parse the ICMP header
void parse_icmp_header(const u_char *packet) {
    struct icmphdr *icmp_header = (struct icmphdr *) packet;

    printf("ICMP Type: %u\n", icmp_header->type);
    printf("ICMP Code: %u\n", icmp_header->code);

    // Additional information for some ICMP types
    switch (icmp_header->type) {
        case ICMP_ECHOREPLY:
            printf("ICMP Echo Reply\n");
            break;
        case ICMP_DEST_UNREACH:
            printf("Destination Unreachable\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf("Source Quench\n");
            break;
        case ICMP_REDIRECT:
            printf("Redirect (change route)\n");
            break;
        case ICMP_ECHO:
            printf("ICMP Echo Request (ping)\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf("Time Exceeded\n");
            break;
        case ICMP_PARAMETERPROB:
            printf("Parameter Problem\n");
            break;
        case ICMP_TIMESTAMP:
            printf("Timestamp Request\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("Timestamp Reply\n");
            break;
        case ICMP_INFO_REQUEST:
            printf("Information Request\n");
            break;
        case ICMP_INFO_REPLY:
            printf("Information Reply\n");
            break;
        default:
            printf("Other ICMP type\n");
            break;
    }
}