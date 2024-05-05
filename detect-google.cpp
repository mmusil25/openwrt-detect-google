#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const char *payload = (char *)(packet + 54); // Adjusted offset to skip Ethernet, IP, and TCP headers
    if (strstr(payload, "Host: www.google.com")) {
        printf("Google.com accessed\n");
        // Signal your shell script here
    }
}

int main() {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "ip src 192.168.2.148 and tcp"; // Filter for IP source and TCP protocol

    // Open the device for sniffing.
    descr = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    // Compile and set the packet filter
    if (pcap_compile(descr, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
        pcap_close(descr);
        return 1;
    }

    if (pcap_setfilter(descr, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
        pcap_close(descr);
        return 1;
    }

    // Start packet processing loop, run indefinitely
    if (pcap_loop(descr, -1, packetHandler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(descr));
        pcap_close(descr);
        return 1;
    }

    // Close the session
    pcap_close(descr);
    return 0;
}
