#!/bin/bash
# Block telnet to MachineB
ufw deny out proto tcp to 10.0.2.4 port 23
# Block HTTP to 'http://ceng.metu.edu.tr'
ufw deny out proto tcp to 144.122.145.146 port 80
# Show that it actually worked
curl --verbose --header "Host: ceng.metu.edu.tr" http://ceng.metu.edu.tr --connect-timeout 5
# Disable all outgoing HTTPS
ufw deny out 443

# Add/change these lines to /etc/ufw/before.rules block all ICMP traffic
#
# ok icmp codes for INPUT
#-A ufw-before-input -p icmp --icmp-type destination-unreachable -j DROP
#-A ufw-before-input -p icmp --icmp-type source-quench -j DROP
#-A ufw-before-input -p icmp --icmp-type time-exceeded -j DROP
#-A ufw-before-input -p icmp --icmp-type parameter-problem -j DROP
#-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
#-A ufw-before-output -p icmp -m state --state NEW,ESTABLISHED,RELATED -j DROP
#-A ufw-before-output -p icmp -m state --state ESTABLISHED,RELATED -j DROP

