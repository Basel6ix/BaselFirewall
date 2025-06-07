# BaselFirewall Complete User Guide

**Author:** B. Abu-Radaha  
**Supervisor:** M. Nabrawi  
**College:** Hittien College  
**Date:** May 2025

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Security Features](#security-features)
5. [Attack Testing](#attack-testing)
6. [Monitoring and Logging](#monitoring-and-logging)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Configuration](#advanced-configuration)

## Introduction

BaselFirewall is a comprehensive network security solution that combines traditional firewall capabilities with advanced intrusion detection and prevention features. This guide will walk you through all aspects of the system.

### Key Features
- Packet filtering with iptables
- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- DoS protection
- Stateful inspection
- Real-time monitoring
- Comprehensive logging

## Installation

### Prerequisites
- Python 3.x
- iptables
- tcpdump
- Root/sudo access

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/BaselFirewall.git
   cd BaselFirewall
   ```

2. Install dependencies:
   ```bash
   sudo pip3 install -r requirements.txt
   ```

3. Run the setup script:
   ```bash
   sudo ./setup_firewall.sh
   ```

4. Start the service:
   ```bash
   sudo systemctl enable baselfirewall.service
   sudo systemctl start baselfirewall.service
   ```

## Basic Usage

### Starting the Firewall
```bash
sudo python3 main.py
```

You'll see the main menu:
```
=== Basel Firewall Launcher ===
Firewall Status: ENABLED
1. Launch CLI
2. Launch GUI
3. Toggle Firewall (Enable/Disable)
0. Exit
```

### Enabling IDS/IPS
```bash
sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"
```

### Checking Status
```bash
sudo systemctl status baselfirewall.service
```

## Security Features

### 1. Packet Filtering
- Default policies set to DROP
- Stateful inspection
- Custom rule support
- Rate limiting

### 2. IDS/IPS
- Real-time packet inspection
- Signature-based detection
- Anomaly detection
- Automatic blocking

### 3. DoS Protection
- SYN flood protection
- ICMP flood protection
- Rate limiting
- Connection tracking

## Attack Testing

### Setup
1. Attacker (Ubuntu):
   - Install required tools:
     ```bash
     sudo apt-get install hping3 nmap
     ```

2. Defender (Kali):
   - Ensure BaselFirewall is running
   - Enable IDS/IPS
   - Monitor logs

### Test Scenarios

#### 1. Port Scanning
```bash
# On attacker machine
sudo nmap -sS <target_ip>
```

#### 2. SYN Flood
```bash
# On attacker machine
sudo hping3 -S -p 80 -c 1000 <target_ip>
```

#### 3. ICMP Flood
```bash
# On attacker machine
sudo hping3 -1 -c 1000 <target_ip>
```

## Monitoring and Logging

### Log Files
- Firewall logs: `/var/log/baselfirewall/firewall.log`
- IDS/IPS logs: `/var/log/baselfirewall/ids_ips.log`
- Alert logs: `/var/log/baselfirewall/alerts.log`

### Monitoring Commands
```bash
# View firewall logs
sudo tail -f /var/log/baselfirewall/firewall.log

# View alerts
sudo tail -f /var/log/baselfirewall/alerts.log

# Check service status
sudo systemctl status baselfirewall.service
```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check service status
   sudo systemctl status baselfirewall.service
   
   # Check logs
   sudo journalctl -u baselfirewall.service
   ```

2. **IDS/IPS Not Working**
   ```bash
   # Verify interface
   ip addr show
   
   # Check permissions
   sudo chown -R root:root /var/log/baselfirewall
   sudo chmod -R 640 /var/log/baselfirewall
   ```

3. **High CPU Usage**
   - Check log rotation
   - Verify rule complexity
   - Monitor traffic patterns

## Advanced Configuration

### Configuration Files
- Main config: `config/firewall_config.json`
- Service config: `/etc/systemd/system/baselfirewall.service`
- Log rotation: `/etc/logrotate.d/baselfirewall`

### Custom Rules
Add custom rules in `config/firewall_config.json`:
```json
{
    "custom_rules": [
        {
            "chain": "INPUT",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "destination": "any",
            "action": "ACCEPT"
        }
    ]
}
```

### Performance Tuning
1. Adjust scan intervals
2. Optimize rule order
3. Implement log rotation
4. Monitor resource usage

## Best Practices

1. **Regular Maintenance**
   - Update signatures
   - Review logs
   - Check performance
   - Verify backups

2. **Security**
   - Regular updates
   - Access control
   - Log protection
   - Monitoring

3. **Performance**
   - Rule optimization
   - Resource monitoring
   - Log management
   - Regular cleanup

## Additional Resources

- [API Documentation](API.md)
- [Security Guide](SECURITY.md)
- [Performance Guide](PERFORMANCE.md)
- [Attack Testing Guide](attacks.md)
- [Technical Documentation](technical/)

--- 