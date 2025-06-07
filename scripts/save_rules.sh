#!/bin/bash

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Create directory if it doesn't exist
sudo mkdir -p /etc/iptables

# Make the script executable
chmod +x "$0" 