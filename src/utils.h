#ifndef UTILS_H
#define UTILS_H

#include <pcap.h>


void set_pcap_handle(pcap_t *handle);

void sigint_handler(int signum);

void initialize_signal_handler();

#endif // UTILS_H