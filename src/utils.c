#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "utils.h"

static pcap_t *pcap_handle = NULL; 

void set_pcap_handle(pcap_t *handle) {
    pcap_handle = handle;
}

// SIGINT signal handler
void sigint_handler(int signum) {
    printf("SIGINT received, terminating...\n");
    if (pcap_handle != NULL) {
        // Break the pcap_loop
        pcap_breakloop(pcap_handle);  
        pcap_close(pcap_handle);      
    }
    exit(0);
}

// Initialize the signal handler
void initialize_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}
