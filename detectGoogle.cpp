#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <gpiod.h>
#include <iostream>

using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const char *payload = (char *)(packet + 54); // Adjusted offset to skip Ethernet, IP, and TCP headers
    printf("Packet captured: length=%d\n", pkthdr->len); // Debug: output packet length
    fflush(stdout); // Flush the standard output buffer

    if (strstr(payload, "Host: www.google.com")) {
        system("/usr/sbin/gpio_ctrl_script.sh 22 out 1");
        printf("Google.com accessed\n");  // Signal detected access to Google
	usleep(1000000);
        system("/usr/sbin/gpio_ctrl_script.sh 22 out 0");
	fflush(stdout); // Flush the standard output buffer
    } else {
        printf("Packet does not contain 'Host: www.google.com'\n");  // Debug: packet does not match
        fflush(stdout); // Flush the standard output buffer
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <device> <IP>\n", argv[0]);
        return 1;
	    }

    char *device = argv[1];
    char *ip = argv[2];

    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "ip src %s and tcp", ip); // Dynamically created filter expression

    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    printf("Opening device %s for sniffing...\n", device);
    fflush(stdout);

    // Open the device for sniffing.
    descr = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        fflush(stderr);
        return 1;
    }

    printf("Device opened successfully.\n");
    fflush(stdout);

    printf("Compiling filter: %s\n", filter_exp);
    fflush(stdout);

    // Compile and set the packet filter
    if (pcap_compile(descr, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
        fflush(stderr);
        pcap_close(descr);
        return 1;
    }

    printf("Filter compiled successfully. Setting filter...\n");
    fflush(stdout);

    if (pcap_setfilter(descr, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
        fflush(stderr);
        pcap_close(descr);
        return 1;
    }

    printf("Filter set successfully. Starting packet loop...\n");
    fflush(stdout);

    // Start packet processing loop, run indefinitely
    if (pcap_loop(descr, -1, packetHandler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(descr));
        fflush(stderr);
        pcap_close(descr);
        return 1;
    }

    printf("Closing session...\n");
    fflush(stdout);

    // Close the session
    pcap_close(descr);
    return 0;
}
