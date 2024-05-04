#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "utils.h"
#include "sniffer.h"

// Initialize the sniffer
pcap_t* initialize_sniffer(char *interface, int port_src, int port_dst, int filter_tcp, int filter_udp,
                           int filter_arp, int filter_ndp, int filter_icmp4, int filter_icmp6,
                           int filter_igmp, int filter_mld) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for stderr
    pcap_t *handle;                // Session handle
    char filter_exp[512] = "";     // Filter expression

    // Open the session in promiscuous mode
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        exit(1);
    }
    set_pcap_handle(handle);

    // Construct the filter expression
    construct_filter_expression(filter_exp, sizeof(filter_exp), port_src, port_dst, 
                                filter_tcp, filter_udp, filter_arp, filter_ndp, 
                                filter_icmp4, filter_icmp6, filter_igmp, filter_mld);
    // Set the filter
    if (set_filter(handle, filter_exp) != 0) {
        pcap_close(handle);
        fprintf(stderr, "Failed to set filter.\n");
        exit(1);
    }
    return handle;
}

// Start packet capturing
int start_packet_capturing(pcap_t *handle, int count) {
    // Initialize the number of packets to capture (-n option)
    if (pcap_loop(handle, count, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error occurred during packet capturing: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return 0;
}

// Packet handler
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Lengths 
    int length = header->caplen;                             // Length of portion present
    int total_length = header->len;                          // Length of the packet
    parse_ethernet_header(packet, header->ts, total_length); // Parse the Ethernet header and others (parser.c)
    print_packet_data(packet, length);                       // Function to print byte_offset (parser.c)
}

// Construct the filter expression
void construct_filter_expression(char *filter_exp, int max_len, int port_src, int port_dst, 
                                 int filter_tcp, int filter_udp, int filter_arp, int filter_ndp,
                                 int filter_icmp4, int filter_icmp6, int filter_igmp, int filter_mld) {
    int offset = 0;          // Offset for the filter expression
    int first_condition = 1; // Flag to check if it's the first condition
    offset += snprintf(filter_exp + offset, max_len - offset, "(");
    // Function to optimize the construction of the filter expression
    void add_condition(const char* condition) {
        if (!first_condition) {
            offset += snprintf(filter_exp + offset, max_len - offset, " or ");
        }
        offset += snprintf(filter_exp + offset, max_len - offset, "(%s)", condition);
        first_condition = 0;
    }
    // TCP and UDP filters with port_src and port_dst logic
    if (filter_tcp) {
        char tcp_filter[256] = "tcp";
        if (port_src > -1 || port_dst > -1) {
            strcat(tcp_filter, " and (");
            if (port_src > -1) {
                snprintf(tcp_filter + strlen(tcp_filter), sizeof(tcp_filter) - strlen(tcp_filter), "src port %d", port_src);
                if (port_dst > -1) strcat(tcp_filter, " or ");
            }
            if (port_dst > -1) {
                snprintf(tcp_filter + strlen(tcp_filter), sizeof(tcp_filter) - strlen(tcp_filter), "dst port %d", port_dst);
            }
            strcat(tcp_filter, ")");
        }
        add_condition(tcp_filter);
    }
    if (filter_udp) {
        char udp_filter[256] = "udp";
        if (port_src > -1 || port_dst > -1) {
            strcat(udp_filter, " and (");
            if (port_src > -1) {
                snprintf(udp_filter + strlen(udp_filter), sizeof(udp_filter) - strlen(udp_filter), "src port %d", port_src);
                if (port_dst > -1) strcat(udp_filter, " or ");
            }
            if (port_dst > -1) {
                snprintf(udp_filter + strlen(udp_filter), sizeof(udp_filter) - strlen(udp_filter), "dst port %d", port_dst);
            }
            strcat(udp_filter, ")");
        }
        add_condition(udp_filter);
    }
    // ARP, ICMPv4, IGMP filters
    if (filter_arp) add_condition("arp");
    if (filter_icmp4) add_condition("icmp");
    if (filter_igmp) add_condition("igmp");
    // Special filters for ICMPv6, NDP, MLD
    if (filter_icmp6 || filter_ndp || filter_mld) {
        char icmp6_filter[1024] = "";
        int first_icmp6_condition = 1;
        // If no other ICMPv6 filters are set
        if (!(filter_ndp || filter_mld)){
            strcat(icmp6_filter, "icmp6");
            add_condition(icmp6_filter);
        }
        else {
            strcat(icmp6_filter, "icmp6 and (");
            if (filter_ndp) {
                if (!first_icmp6_condition) strcat(icmp6_filter, " or ");
                strcat(icmp6_filter, "icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137");
                first_icmp6_condition = 0;
            }
            if (filter_mld) {
                if (!first_icmp6_condition) strcat(icmp6_filter, " or ");
                strcat(icmp6_filter, "icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp6[0] == 143");
            }
            strcat(icmp6_filter, ")");
            add_condition(icmp6_filter);
        }
    }
    offset += snprintf(filter_exp + offset, max_len - offset, ")");
}

// Set the filter
int set_filter(pcap_t *handle, const char *filter_exp) {
    struct bpf_program fp;         // Compiled filter expression    
    bpf_u_int32 net = 0;           // The address of the network
    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }
    // Setting the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        exit(1);
    }
    pcap_freecode(&fp);
    return 0;
}