# Deployment Guide

## Overview
This guide provides detailed instructions for deploying BaselFirewall in various environments, from development to production.

## System Requirements

### Hardware Requirements
- CPU: 2+ cores
- RAM: 4GB minimum
- Storage: 20GB minimum
- Network: 2 NICs recommended

### Software Requirements
- Operating System: Linux (Ubuntu 20.04+ recommended)
- Python 3.8 or higher
- systemd
- iptables/nftables
- libnetfilter-queue

### Network Requirements
- Dedicated management interface
- Separate interfaces for internal/external networks
- Static IP configuration recommended
- Internet connectivity for updates

## Installation Methods

### Package Installation
```bash
# Add repository
curl -fsSL https://repo.baselfirewall.org/gpg | sudo gpg --dearmor -o /usr/share/keyrings/baselfirewall-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/baselfirewall-archive-keyring.gpg] https://repo.baselfirewall.org/apt stable main" | sudo tee /etc/apt/sources.list.d/baselfirewall.list

# Update and install
sudo apt update
sudo apt install baselfirewall
```

### Source Installation
```bash
# Clone repository
git clone https://github.com/Basel6ix/BaselFirewall.git
cd BaselFirewall

# Install dependencies
pip3 install -r requirements.txt

# Install package
sudo python3 setup.py install
```

### Docker Installation
```bash
# Pull image
docker pull baselfirewall/baselfirewall:latest

# Run container
docker run -d \
  --name baselfirewall \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /etc/baselfirewall:/etc/baselfirewall \
  baselfirewall/baselfirewall:latest
```

## Configuration

### Network Setup
```bash
# Configure interfaces
sudo nano /etc/netplan/01-netcfg.yaml

# Example configuration
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses: [192.168.1.1/24]
    eth1:
      dhcp4: yes
```

### Firewall Configuration
```bash
# Basic configuration
sudo baselfirewall-cli config init

# Import rules
sudo baselfirewall-cli rules import rules.yaml

# Enable features
sudo baselfirewall-cli feature enable ids
sudo baselfirewall-cli feature enable dos
```

### Security Setup
```bash
# Configure IDS
sudo baselfirewall-cli ids config sensitivity high

# Setup DoS protection
sudo baselfirewall-cli dos config rate 100

# Configure NAT
sudo baselfirewall-cli nat enable
```

## Deployment Environments

### Development
```bash
# Install development dependencies
pip3 install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Start in debug mode
sudo baselfirewall-cli start --debug
```

### Testing
```bash
# Run integration tests
sudo baselfirewall-cli test integration

# Load test configuration
sudo baselfirewall-cli config load test.yaml

# Monitor logs
tail -f /var/log/baselfirewall/debug.log
```

### Production
```bash
# Enable service
sudo systemctl enable baselfirewall

# Start service
sudo systemctl start baselfirewall

# Check status
sudo systemctl status baselfirewall
```

## High Availability

### Active-Passive Setup
```bash
# Install keepalived
sudo apt install keepalived

# Configure VRRP
sudo nano /etc/keepalived/keepalived.conf

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    authentication {
        auth_type PASS
        auth_pass secret
    }
    virtual_ipaddress {
        192.168.1.100
    }
}
```

### Load Balancing
```bash
# Install HAProxy
sudo apt install haproxy

# Configure backend
sudo nano /etc/haproxy/haproxy.cfg

backend baselfirewall
    balance roundrobin
    server fw1 192.168.1.101:8080 check
    server fw2 192.168.1.102:8080 check
```

## Monitoring

### System Monitoring
```bash
# Install monitoring tools
sudo apt install prometheus node-exporter

# Configure Prometheus
sudo nano /etc/prometheus/prometheus.yml

scrape_configs:
  - job_name: 'baselfirewall'
    static_configs:
      - targets: ['localhost:9100']
```

### Log Management
```bash
# Configure rsyslog
sudo nano /etc/rsyslog.d/baselfirewall.conf

# Forward logs
*.* @logserver:514

# Restart service
sudo systemctl restart rsyslog
```

## Backup and Recovery

### Backup Configuration
```bash
# Create backup
sudo baselfirewall-cli backup create

# Schedule backup
sudo nano /etc/cron.d/baselfirewall-backup

0 0 * * * root /usr/local/bin/baselfirewall-cli backup create
```

### Disaster Recovery
```bash
# Restore from backup
sudo baselfirewall-cli backup restore latest.tar.gz

# Verify restoration
sudo baselfirewall-cli config verify
```

## Security Hardening

### System Hardening
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo baselfirewall-cli rules harden

# Set permissions
sudo chmod 600 /etc/baselfirewall/*.yaml
```

### Service Hardening
```bash
# Configure SELinux
sudo semanage port -a -t baselfirewall_port_t -p tcp 8080

# Set capabilities
sudo setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/baselfirewall
```

## Troubleshooting

### Common Issues
1. Service won't start
2. Rules not applying
3. High CPU usage
4. Memory leaks
5. Network issues

### Diagnostics
```bash
# Check logs
sudo journalctl -u baselfirewall -n 100

# Test configuration
sudo baselfirewall-cli config test

# Check connectivity
sudo baselfirewall-cli network test
```

## Maintenance

### Regular Tasks
```bash
# Update signatures
sudo baselfirewall-cli update signatures

# Clean logs
sudo baselfirewall-cli logs clean

# Check health
sudo baselfirewall-cli health check
```

### Performance Tuning
```bash
# Optimize rules
sudo baselfirewall-cli rules optimize

# Adjust resources
sudo baselfirewall-cli resource adjust

# Monitor performance
sudo baselfirewall-cli stats show
``` 