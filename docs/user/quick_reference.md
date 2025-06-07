# BaselFirewall Quick Reference Guide

## Basic Commands

### Service Management
```bash
# Start firewall
sudo systemctl start baselfirewall.service

# Stop firewall
sudo systemctl stop baselfirewall.service

# Check status
sudo systemctl status baselfirewall.service

# Enable on boot
sudo systemctl enable baselfirewall.service
```

### IDS/IPS Control
```bash
# Enable IDS/IPS
sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"

# Disable IDS/IPS
sudo python3 -c "from firewall.ids_ips import disable_ids_ips; disable_ids_ips()"

# Check IDS/IPS status
sudo python3 -c "from firewall.ids_ips import check_status; check_status()"
```

### Log Monitoring
```bash
# View firewall logs
sudo tail -f /var/log/baselfirewall/firewall.log

# View IDS/IPS alerts
sudo tail -f /var/log/baselfirewall/alerts.log

# View performance logs
sudo tail -f /var/log/baselfirewall/performance.log
```

## Common Tasks

### 1. Adding Custom Rules
```bash
# Add rule via CLI
sudo python3 -c "from firewall.rules import add_rule; add_rule('INPUT', 'tcp', '192.168.1.0/24', 'ACCEPT')"

# Add rule via config
# Edit config/firewall_config.json
{
    "custom_rules": [
        {
            "chain": "INPUT",
            "protocol": "tcp",
            "source": "192.168.1.0/24",
            "action": "ACCEPT"
        }
    ]
}
```

### 2. Monitoring Attacks
```bash
# Monitor port scans
sudo tail -f /var/log/baselfirewall/alerts.log | grep "PORT_SCAN"

# Monitor DoS attempts
sudo tail -f /var/log/baselfirewall/alerts.log | grep "DOS"

# Monitor blocked IPs
sudo iptables -L INPUT -n -v | grep DROP
```

### 3. Performance Checks
```bash
# Check CPU usage
ps aux | grep python3 | grep -v grep

# Check memory usage
free -m

# Check disk usage
df -h /var/log/baselfirewall
```

## Troubleshooting

### Common Issues

1. **Service Won't Start**
   ```bash
   # Check logs
   sudo journalctl -u baselfirewall.service
   
   # Verify permissions
   sudo chown -R root:root /var/log/baselfirewall
   sudo chmod -R 640 /var/log/baselfirewall
   ```

2. **IDS/IPS Not Working**
   ```bash
   # Check interface
   ip addr show
   
   # Verify tcpdump
   sudo tcpdump -i eth0 -c 1
   ```

3. **High CPU Usage**
   ```bash
   # Check process
   ps aux | grep python3
   
   # Check logs
   sudo tail -f /var/log/baselfirewall/performance.log
   ```

## Configuration Files

### Main Configuration
- Location: `config/firewall_config.json`
- Purpose: Main firewall settings
- Access: Requires root/sudo

### Service Configuration
- Location: `/etc/systemd/system/baselfirewall.service`
- Purpose: Service management
- Access: Requires root/sudo

### Log Configuration
- Location: `/etc/logrotate.d/baselfirewall`
- Purpose: Log rotation
- Access: Requires root/sudo

## Security Checks

### Daily Checks
1. Review firewall logs
2. Check for new alerts
3. Monitor system resources
4. Verify service status

### Weekly Checks
1. Review blocked IPs
2. Check rule effectiveness
3. Update signatures
4. Backup configuration

### Monthly Checks
1. Review performance
2. Update system
3. Check disk space
4. Verify backups

## Emergency Procedures

### 1. Complete Shutdown
```bash
sudo systemctl stop baselfirewall.service
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

### 2. Quick Restart
```bash
sudo systemctl restart baselfirewall.service
```

### 3. Reset to Default
```bash
sudo python3 -c "from firewall.setup import reset_to_default; reset_to_default()"
```

## Contact Information

### Support Channels
- GitHub Issues: [Repository Issues]
- Email: support@baselfirewall.com
- Documentation: [Documentation Link]
- Community Forum: [Forum Link]

--- 