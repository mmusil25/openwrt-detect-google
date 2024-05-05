## Intro 

`detectGoogle.cpp` is a script that detects when a certain device accesses www.google.com and then outputs a message to the command line saying "Google.com accessed". It is meant to be used as a package on an OpenWRT router. It is a part of a tutorial and to understand its usage please read the tutorial. [Link to tutorial](https://www.markmusil.click/openwrt-embedded-c-gpio/) 

`ping_google.sh` is a bash script that sends HTTP requests to www.google.com very rapidly in order to test `detectGoogle.cpp`

## Usage

Usage: detectGoogle <device> <IP>

Where:
  <device>  Specifies the network interface on which to sniff packets.
            Example: eth0, wlan0, br-lan

  <IP>      Specifies the source IP address to filter the incoming packets.
            This should be an IPv4 address from which you want to capture traffic.
            Example: 192.168.1.1

Description:
  This program captures and analyzes packets passing through the specified network device.
  It specifically looks for packets coming from the specified IP address and checks if they
  contain HTTP headers targeting 'www.google.com'. If such packets are detected,
  the program will output a message indicating that access to Google.com has been observed.

Examples:
  detectGoogle eth0 192.168.1.1
  This command will start the packet sniffer on the 'eth0' interface, filtering packets
  that originate from the IP address 192.168.1.1 and checking for access to Google.com.

  detectGoogle wlan0 10.0.0.5
  This command will run the packet sniffer on the 'wlan0' interface, looking for packets
  from 10.0.0.5 that access www.google.com.
