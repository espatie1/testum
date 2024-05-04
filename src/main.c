#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include "sniffer.h"
#include "utils.h"

// Array of long option
struct option long_options[] = {
    {"interface", required_argument, NULL, 'i'},
    {"port-source", required_argument, NULL, 's'},
    {"port-destination", required_argument, NULL, 'd'},
    {"tcp", no_argument, NULL, 't'},
    {"udp", no_argument, NULL, 'u'},
    {"arp", no_argument, NULL, 'a'},
    {"ndp", no_argument, NULL, 'N'},  
    {"icmp4", no_argument, NULL, '4'},
    {"icmp6", no_argument, NULL, '6'},
    {"igmp", no_argument, NULL, 'g'},
    {"mld", no_argument, NULL, 'm'},
    {"num", required_argument, NULL, 'n'},  
    {0, 0, 0, 0}
};

void print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    for (temp = interfaces; temp; temp = temp->next) {
        printf("%s\n", temp->name);
    }
    pcap_freealldevs(interfaces);
}

void usage(char *program_name) {
    printf("Usage: %s [-i interface | --interface interface] "
           "[--port-source port] [--port-destination port] "
           "[--tcp] [--udp] [--arp] [--ndp] [--icmp4] [--icmp6] "
           "[--igmp] [--mld] [-n num]\n", program_name);
    printf("Options:\n");
    printf("  -i, --interface       Specify the interface to capture packets on\n");
    printf("  --port-source         Specify the source port to filter packets\n");
    printf("  --port-destination    Specify the destination port to filter packets\n");
    printf("  --tcp                 Capture only TCP packets\n");
    printf("  --udp                 Capture only UDP packets\n");
    printf("  --arp                 Capture only ARP frames\n");
    printf("  --ndp                 Capture only NDP packets\n");
    printf("  --icmp4               Capture only ICMPv4 packets\n");
    printf("  --icmp6               Capture only ICMPv6 packets\n");
    printf("  --igmp                Capture only IGMP packets\n");
    printf("  --mld                 Capture only MLD packets\n");
    printf("  -n num                Number of packets to capture\n");
    exit(0);
}

// Main function
int main(int argc, char **argv) {
    // Parsing arguments
    char *interface = NULL;
    int port_src = -1, port_dst = -1;
    int count = 1;  
    int filter_tcp = 0, filter_udp = 0, filter_arp = 0, filter_ndp = 0;
    int filter_icmp4 = 0, filter_icmp6 = 0, filter_igmp = 0, filter_mld = 0;
    int option_index = 0, i_flag = 0;  
    int option;
    // Parsing arguments
    while ((option = getopt_long(argc, argv, "i:n:p:d:tuaN456gmn", long_options, &option_index)) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                i_flag = 1;  
                break;
            case 'n':
                count = atoi(optarg);
                break;
            case 'p':
                port_src = atoi(optarg);
                port_dst = atoi(optarg);
                break;
            case 'd':
                port_dst = atoi(optarg);
                break;
            case 't':
                filter_tcp = 1;
                break;
            case 'u':
                filter_udp = 1;
                break;
            case 'a':
                filter_arp = 1;
                break;
            case 'N':
                filter_ndp = 1;
                break;
            case '4':
                filter_icmp4 = 1;
                break;
            case '6':
                filter_icmp6 = 1;
                break;
            case 'g':
                filter_igmp = 1;
                break;
            case 'm':
                filter_mld = 1;
                break;
            case 's': 
                port_src = atoi(optarg);
                break;
            case '?':
            default:
                usage(argv[0]);
                break;
        }
    }
    initialize_signal_handler();
    // if no interface is specified, print available interfaces
    if (interface == NULL && i_flag) {
        print_interfaces();
        return 0;
    } else if (interface == NULL) {
        fprintf(stderr, "No interface specified.\n");
        usage(argv[0]);
    }

    // initialize sniffer (sniffer.c)
    pcap_t *handle = initialize_sniffer(interface, port_src, port_dst, filter_tcp, filter_udp,
                                        filter_arp, filter_ndp, filter_icmp4, filter_icmp6,
                                        filter_igmp, filter_mld);
    if (handle == NULL) {
        fprintf(stderr, "Failed to initialize sniffer.\n");
        exit(1);
    }

    // start packet capturing (sniffer.c)
    if (start_packet_capturing(handle, count) != 0) {
        fprintf(stderr, "Failed to start packet capturing.\n");
        pcap_close(handle);
        exit(1);
    }

    // close the session
    pcap_close(handle);
    return 0;
}