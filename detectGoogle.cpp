#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const char *payload = (char *)(packet + 54); // Adjusted offset to skip Ethernet, IP, and TCP headers
    printf("Packet captured: length=%d\n", pkthdr->len); // Debug: output packet length
    fflush(stdout); // Flush the standard output buffer

    if (strstr(payload, "Host: www.google.com")) {
        printf("Google.com accessed\n");  // Signal detected access to Google
        fflush(stdout); // Flush the standard output buffer
    } else {
        printf("Packet does not contain 'Host: www.google.com'\n");  // Debug: packet does not match
        fflush(stdout); // Flush the standard output buffer
    }
}

int main() {
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "ip src 192.168.2.148 and tcp"; // Filter for IP source and TCP protocol

    printf("Opening device for sniffing...\n"); // Debug: Notify opening device
    fflush(stdout); // Flush the standard output buffer

    // Open the device for sniffing.
    descr = pcap_open_live("br-lan", BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        fflush(stderr); // Flush the standard error buffer
        return 1;
    } else {
        printf("Device opened successfully.\n"); // Debug: Device opened successfully
        fflush(stdout); // Flush the standard output buffer
    }

    printf("Compiling filter: %s\n", filter_exp); // Debug: Show the filter expression
    fflush(stdout); // Flush the standard output buffer

    // Compile and set the packet filter
    if (pcap_compile(descr, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
        fflush(stderr); // Flush the standard error buffer
        pcap_close(descr);
        return 1;
    }

    printf("Filter compiled successfully. Setting filter...\n"); // Debug: Filter compiled
    fflush(stdout); // Flush the standard output buffer

    if (pcap_setfilter(descr, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
        fflush(stderr); // Flush the standard error buffer
        pcap_close(descr);
        return 1;
    }

    printf("Filter set successfully. Starting packet loop...\n"); // Debug: Filter set
    fflush(stdout); // Flush the standard output buffer

    // Start packet processing loop, run indefinitely
    if (pcap_loop(descr, -1, packetHandler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(descr));
        fflush(stderr); // Flush the standard error buffer
        pcap_close(descr);
        return 1;
    }

    printf("Closing session...\n"); // Debug: Notify closing session
    fflush(stdout); // Flush the standard output buffer

    // Close the session
    pcap_close(descr);
    return 0;
}
