#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>

pcap_t* initialize_sniffer(char *interface, int port_src, int port_dst, int filter_tcp, int filter_udp,
                           int filter_arp, int filter_ndp, int filter_icmp4, int filter_icmp6,
                           int filter_igmp, int filter_mld);

int start_packet_capturing(pcap_t *handle, int count);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void construct_filter_expression(char *filter_exp, int max_len, int port_src, int port_dst, 
                                 int filter_tcp, int filter_udp, int filter_arp, int filter_ndp,
                                 int filter_icmp4, int filter_icmp6, int filter_igmp, int filter_mld);
int set_filter(pcap_t *handle, const char *filter_exp);

#endif // SNIFFER_H