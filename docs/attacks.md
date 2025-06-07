# BaselFirewall Attack Scenarios

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

## Network Setup

### Device Configuration

#### Defender (Kali Linux with BaselFirewall)
- **OS**: Kali Linux
- **Role**: Defender/Firewall
- **Interfaces**:
  - `eth0`: External interface (Internet-facing)
  - `eth1`: Internal interface (Local network)
  - Internal Network: 192.168.1.0/24

#### Attacker (Ubuntu)
- **OS**: Ubuntu
- **Role**: Attacker
- **Interface**: Connected to defender's network

### Network Configuration

#### 1. NAT Setup on Defender
```bash
# Check current interfaces
ip addr show

# Configure NAT in firewall_config.json
{
    "nat_enabled": true,
    "nat_config": {
        "external_interface": "eth0",
        "internal_interface": "eth1",
        "internal_network": "192.168.1.0/24"
    }
}
```

#### 2. Interface Configuration
```bash
# On Kali (Defender)
# External Interface (eth0)
sudo ip addr add 192.168.0.1/24 dev eth0
sudo ip link set eth0 up

# Internal Interface (eth1)
sudo ip addr add 192.168.1.1/24 dev eth1
sudo ip link set eth1 up

# On Ubuntu (Attacker)
sudo ip addr add 192.168.1.100/24 dev eth0
sudo ip route add default via 192.168.1.1
```

## Attack Scenarios

### 1. Port Scanning Attack

#### Attack Description
- **Type**: Reconnaissance
- **Tool**: Nmap
- **Target**: Defender's interfaces

#### Attack Commands (Ubuntu)
```bash
# Basic port scan
nmap -sS 192.168.1.1

# Aggressive scan
nmap -A 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1
```

#### Defense Configuration (BaselFirewall)
```json
{
    "ids_ips_enabled": true,
    "blocked_ports": [22, 23, 445, 3389],
    "dos_protection_enabled": true
}
```

### 2. DoS Attack

#### Attack Description
- **Type**: Denial of Service
- **Tool**: hping3
- **Target**: Web service (port 80)

#### Attack Commands (Ubuntu)
```bash
# SYN flood attack
sudo hping3 -S -p 80 --flood 192.168.1.1

# ICMP flood attack
sudo hping3 -1 --flood 192.168.1.1
```

#### Defense Configuration (BaselFirewall)
```json
{
    "dos_settings": {
        "syn_flood_rate": 10,
        "icmp_flood_rate": 5,
        "connection_limit": 50,
        "block_time": 300
    }
}
```

### 3. Brute Force Attack

#### Attack Description
- **Type**: Authentication Attack
- **Tool**: Hydra
- **Target**: SSH service

#### Attack Commands (Ubuntu)
```bash
# SSH brute force attempt
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh
```

#### Defense Configuration (BaselFirewall)
```json
{
    "authentication": {
        "max_attempts": 3,
        "lockout_time": 300,
        "session_timeout": 1800
    }
}
```

### 4. Man-in-the-Middle Attack

#### Attack Description
- **Type**: Network Interception
- **Tool**: ARP Spoofing (arpspoof)
- **Target**: Network traffic

#### Attack Commands (Ubuntu)
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing
arpspoof -i eth0 -t 192.168.1.1 192.168.1.2
```

#### Defense Configuration (BaselFirewall)
```json
{
    "ids_settings": {
        "scan_interfaces": ["eth0", "eth1"],
        "alert_threshold": 5,
        "scan_interval": 60
    }
}
```

## Monitoring and Analysis

### 1. Traffic Monitoring
```bash
# On Defender (Kali)
# Monitor traffic on interfaces
tcpdump -i eth0
tcpdump -i eth1

# View firewall logs
tail -f /var/log/baselfirewall/firewall.log
```

### 2. Attack Detection
```bash
# Check IDS alerts
tail -f /var/log/baselfirewall/ids.log

# View blocked IPs
sudo iptables -L INPUT -n -v
```

### 3. Performance Impact
```bash
# Monitor system resources
htop
iftop -i eth0
iftop -i eth1
```

## Testing Checklist

### Pre-Attack Setup
- [ ] Verify network interfaces are properly configured
- [ ] Confirm NAT is working correctly
- [ ] Test connectivity between devices
- [ ] Enable logging and monitoring
- [ ] Configure firewall rules

### During Attack
- [ ] Monitor system resources
- [ ] Check firewall logs
- [ ] Verify defense mechanisms
- [ ] Document attack patterns
- [ ] Capture relevant metrics

### Post-Attack Analysis
- [ ] Review log files
- [ ] Analyze blocked attempts
- [ ] Verify system integrity
- [ ] Document findings
- [ ] Update security measures

## Troubleshooting

### Common Issues

1. **NAT Configuration**
```bash
# Check NAT status
sudo iptables -t nat -L

# Verify IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Reset NAT rules
sudo iptables -t nat -F
```

2. **Interface Problems**
```bash
# Check interface status
ip link show

# Restart networking
sudo systemctl restart networking

# Verify routing
ip route show
```

3. **Firewall Issues**
```bash
# Reset firewall rules
sudo python3 main.py
# Select option to reset configuration

# Check firewall status
sudo iptables -L

# Verify configuration
cat config/firewall_config.json
``` 