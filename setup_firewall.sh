#!/bin/bash

# Stop the service first
sudo systemctl stop baselfirewall.service

# Flush existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -Z

# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow SSH (port 22)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

# Allow DNS
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Save rules
sudo sh -c 'iptables-save > /etc/iptables/rules.v4'

# Create log directory if it doesn't exist
sudo mkdir -p /var/log/baselfirewall
sudo touch /var/log/baselfirewall/firewall.log
sudo chmod 644 /var/log/baselfirewall/firewall.log

# Restart the service
sudo systemctl daemon-reload
sudo systemctl restart baselfirewall.service

echo "Firewall rules have been set up and service has been restarted." 