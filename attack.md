# BaselFirewall Attack Examples and Demonstrations

This document provides examples and explanations of various attacks that BaselFirewall can detect and prevent. Use these examples during your presentation to demonstrate the firewall's capabilities.

## 1. Basic Firewall Rules

### IP Blocking Example
```bash
# Attempt to connect from blocked IP (192.168.1.100)
ssh user@target_server
# Result: Connection refused
```

### Port Blocking Example
```bash
# Attempt to connect to blocked port 8080
curl http://target_server:8080
# Result: Connection refused
```

## 2. DoS Protection

### SYN Flood Attack
```bash
# Simulate SYN flood attack
hping3 -S -p 80 --flood target_server
# BaselFirewall detects and blocks the attacking IP
```

### ICMP Flood Attack
```bash
# Simulate ICMP flood
ping -f target_server
# BaselFirewall rate limits ICMP packets
```

## 3. IDS/IPS Features

### Brute Force Detection
```bash
# Multiple failed SSH attempts
for i in {1..10}; do ssh user@target_server; done
# BaselFirewall detects and blocks after 5 failed attempts
```

### Port Scanning Detection
```bash
# Attempt port scan
nmap -p- target_server
# BaselFirewall detects scanning activity
```

## 4. NAT Functionality

### NAT Configuration Example
```bash
# Internal client (192.168.1.100) accessing internet
curl http://example.com
# Traffic is NATed through external interface
```

## 5. Stateful Inspection

### Connection Tracking
```bash
# Legitimate established connection
nc -l 12345  # On server
nc server 12345  # On client
# BaselFirewall allows established connection
```

## 6. Logging and Alerts

### Attack Detection Log Example
```
2024-03-20 10:15:23 WARNING: Multiple failed login attempts from IP 192.168.1.10
2024-03-20 10:15:24 ALERT: IP 192.168.1.10 blocked for suspicious activity
```

## Demonstration Tips

1. Start with a clean configuration (empty allowed_ips and blocked_ports)
2. Demonstrate basic firewall rules first
3. Show real-time logs during attack simulations
4. Highlight how each security feature responds to threats
5. Use the GUI to show real-time alerts and configuration changes

## Safety Note

These examples are for demonstration purposes only. Always perform security testing in a controlled environment. 