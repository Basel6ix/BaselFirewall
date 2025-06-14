# BaselFirewall Rules Explanation

## Overview
This document explains the iptables rules implemented in the BaselFirewall system. These rules provide a comprehensive security setup with protection against common network attacks.

## Default Policies and Initial Setup
```bash
iptables -F
iptables -X
iptables -Z
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
```
- `-F`: Flushes all existing rules
- `-X`: Deletes all user-defined chains
- `-Z`: Resets all packet and byte counters
- Default policies:
  - `INPUT`: DROP (deny all incoming traffic by default)
  - `FORWARD`: DROP (deny all forwarding traffic)
  - `OUTPUT`: ACCEPT (allow all outgoing traffic)

## Connection Tracking
```bash
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
- Allows packets that are part of existing connections
- `ESTABLISHED`: Packets that belong to an existing connection
- `RELATED`: Packets that are starting a new connection but are related to an existing one

## Loopback Interface
```bash
iptables -A INPUT -i lo -j ACCEPT
```
- Allows all traffic on the loopback interface (localhost)
- Essential for many applications that communicate locally

## ICMP (Ping) Protection
```bash
iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP
```
- Rate limits ICMP traffic to prevent ping floods
- Allows 1 ping per second with a burst of 5
- Drops all other ICMP traffic

## DNS Traffic
```bash
iptables -A INPUT -p udp --sport 53 -j ACCEPT
```
- Allows incoming DNS responses (UDP port 53)
- Essential for domain name resolution

## SSH Brute Force Protection
```bash
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```
- Implements rate limiting for SSH connections
- Allows only 4 new connection attempts within 60 seconds
- Blocks IP addresses that exceed this limit
- Accepts legitimate SSH traffic

## SYN Flood Protection
```bash
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```
- Protects against SYN flood attacks
- Limits new TCP connections to 1 per second with a burst of 3
- Drops excessive SYN packets

## Logging
```bash
iptables -A INPUT -j LOG --log-prefix "DROPPED_INPUT: " --log-level 4
iptables -A FORWARD -j LOG --log-prefix "DROPPED_FORWARD: " --log-level 4
```
- Logs all dropped packets for both INPUT and FORWARD chains
- Helps in monitoring and troubleshooting
- Log entries are written to system logs with descriptive prefixes

## Security Benefits
1. **Default Deny Policy**: Blocks all traffic unless explicitly allowed
2. **Connection Tracking**: Maintains state of legitimate connections
3. **DDoS Protection**: 
   - SYN flood protection
   - ICMP flood protection
4. **Brute Force Prevention**: Rate limits SSH connection attempts
5. **Logging**: Provides audit trail of blocked traffic

## Maintenance
- Rules can be reapplied by running `sudo ./firewall_rules.sh`
- Logs can be monitored in system log files
- Rules can be viewed using `iptables -L -v -n --line-numbers` 