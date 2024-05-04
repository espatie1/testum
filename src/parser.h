#ifndef PARSER_H
#define PARSER_H

#include <netinet/ip.h>
#include <netinet/ip6.h>

void parse_ethernet_header(const u_char *packet, struct timeval ts, int length);

void parse_arp_header(const u_char *packet);

void parse_ip_header(const u_char *packet);

void parse_ipv6_header(const u_char *packet);

void parse_tcp_header(const u_char *packet);

void parse_udp_header(const u_char *packet);

void parse_icmp_header(const u_char *packet);

void parse_icmpv6_header(const u_char *packet);

void parse_igmp_header(const u_char *packet);

void parse_packet(const u_char *packet, struct timeval ts);

void print_packet_data(const u_char *packet, int length);
#endif // PARSER_H