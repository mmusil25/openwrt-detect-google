#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <gpiod.h>
#include <iostream>

using namespace std;

void blinkThreeLEDs(){

    const char *chipname = "gpiochip0";
    struct gpiod_chip *chip;
    struct gpiod_line *lineRed;    // Red LED
    struct gpiod_line *lineButton; // Pushbutton
    struct gpiod_line *lineGreen;   // Green LED
    struct gpiod_line *lineYellow; // yellow LED				    
    int i, val; 


    // Open GPIO chip
    chip = gpiod_chip_open_by_name(chipname);
    if (chip == NULL){
	    perror("Failed to open GPIO chip");
	    return;
    }
    // Open GPIO lines
    lineRed = gpiod_chip_get_line(chip,24);
    if (lineRed == NULL){
	    perror("Failed to open lineRed");
	    return;
    }
    lineGreen = gpiod_chip_get_line(chip,25);
    if (lineGreen == NULL){
	    perror("Failed to open lineGreen");
	    return;
    }
    lineYellow = gpiod_chip_get_line(chip,5);
    if (lineYellow == NULL){
	    perror("Failed to open lineYellow");
	    return;
    }
    // Open LED lines for output
    lineButton = gpiod_chip_get_line(chip, 6);
    if (lineButton == NULL){
	    perror("Failed to open lineButton");
	    return;
    }
    int redOut =  gpiod_line_request_output(lineRed, "example1", 0);
    if (redOut == 0){
	printf("Red line was properly reserved");
    }
    else if (redOut == -1){
	printf("Red line failed to be reserved");
    }


    int greenOut =  gpiod_line_request_output(lineGreen, "example1", 0);
    if (greenOut == 0){
	printf("Green line was properly reserved");
    }
    else if (greenOut == -1){
	printf("Green line failed to be reserved");
    }

    int yellowOut =  gpiod_line_request_output(lineYellow, "example1", 0);
    if (yellowOut == 0){
	printf("yellow line was properly reserved");
    }
    else if (yellowOut == -1){
	printf("yellow line failed to be reserved");
    }
    // Open switch line for input

    int buttonIn =  gpiod_line_request_input(lineButton, "example1");
    if (buttonIn == 0){
	printf("Button line was properly reserved");
    }
    else if (buttonIn == -1){
	printf("Button line failed to be reserved");
    }
    // Blink LEDs in a binary pattern
    i = 0;
    while(true)
    {
	    gpiod_line_set_value(lineRed, (i & 1) != 0);
	    gpiod_line_set_value(lineGreen, (i & 2) != 0);
	    gpiod_line_set_value(lineYellow, (i & 4) != 0);

	    // Read button status and exit if pressed
	    val = gpiod_line_get_value(lineButton);
	    if (val == 0){
		break;
    		}

	    usleep(100000);
	    i++;	    
    }
	gpiod_line_release(lineRed);
	gpiod_line_release(lineGreen);
	gpiod_line_release(lineYellow);
	gpiod_line_release(lineButton);
	gpiod_chip_close(chip);

}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const char *payload = (char *)(packet + 54); // Adjusted offset to skip Ethernet, IP, and TCP headers
    printf("Packet captured: length=%d\n", pkthdr->len); // Debug: output packet length
    fflush(stdout); // Flush the standard output buffer

    if (strstr(payload, "Host: www.google.com")) {
	blinkThreeLEDs();
        printf("Google.com accessed\n");  // Signal detected access to Google
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
