#!/bin/bash

# Flush existing rules and set default policies
iptables -F
iptables -X
iptables -Z
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# ICMP (ping) rate limiting
iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Allow DNS responses
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# SSH protection with rate limiting (4 attempts per 60 seconds)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# SYN flood protection
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Logging dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED_INPUT: " --log-level 4
iptables -A FORWARD -j LOG --log-prefix "DROPPED_FORWARD: " --log-level 4

# Display the rules
iptables -L -v -n --line-numbers 