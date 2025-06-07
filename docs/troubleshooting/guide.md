# BaselFirewall Troubleshooting Guide

**Author:** B. Abu-Radaha  
**Supervisor:** M. Nabrawi  
**College:** Hittien College  
**Date:** May 2025

## Table of Contents
1. [Common Issues](#common-issues)
2. [Service Problems](#service-problems)
3. [IDS/IPS Issues](#idsips-issues)
4. [Performance Issues](#performance-issues)
5. [Network Issues](#network-issues)
6. [Log Analysis](#log-analysis)

## Common Issues

### 1. Service Won't Start
```bash
# Check service status
sudo systemctl status baselfirewall.service

# Check logs
sudo journalctl -u baselfirewall.service

# Verify permissions
sudo chown -R root:root /var/log/baselfirewall
sudo chmod -R 640 /var/log/baselfirewall
```

### 2. Configuration Errors
```bash
# Check config syntax
sudo python3 -c "from firewall.config import validate_config; validate_config()"

# Reset to default
sudo python3 -c "from firewall.setup import reset_to_default; reset_to_default()"

# Backup and restore
sudo cp /etc/baselfirewall/config.json /etc/baselfirewall/config.json.bak
sudo python3 -c "from firewall.setup import restore_config; restore_config()"
```

### 3. Permission Issues
```bash
# Check file permissions
ls -la /var/log/baselfirewall/
ls -la /etc/baselfirewall/

# Fix permissions
sudo chown -R root:root /var/log/baselfirewall
sudo chmod -R 640 /var/log/baselfirewall
sudo chown -R root:root /etc/baselfirewall
sudo chmod -R 640 /etc/baselfirewall
```

## Service Problems

### 1. Service Crashes
```bash
# Check crash logs
sudo journalctl -u baselfirewall.service -b -1

# Check system logs
sudo dmesg | grep python

# Verify Python installation
python3 --version
pip3 list | grep -i firewall
```

### 2. Service Won't Enable
```bash
# Check service file
sudo cat /etc/systemd/system/baselfirewall.service

# Reload systemd
sudo systemctl daemon-reload

# Check dependencies
sudo systemctl list-dependencies baselfirewall.service
```

### 3. Service Performance
```bash
# Check resource usage
ps aux | grep python3 | grep -v grep

# Check system resources
free -m
df -h
top -b -n 1 | grep python
```

## IDS/IPS Issues

### 1. IDS/IPS Not Starting
```bash
# Check interface
ip addr show

# Verify tcpdump
sudo tcpdump -i eth0 -c 1

# Check permissions
sudo chown root:root /usr/sbin/tcpdump
sudo chmod +s /usr/sbin/tcpdump
```

### 2. False Positives
```bash
# Check alert logs
sudo tail -f /var/log/baselfirewall/alerts.log

# Adjust thresholds
sudo python3 -c "from firewall.ids_ips import adjust_threshold; adjust_threshold('port_scan', 10)"

# Update signatures
sudo python3 -c "from firewall.ids_ips import update_signatures; update_signatures()"
```

### 3. Performance Impact
```bash
# Check CPU usage
ps aux | grep python3 | grep -v grep

# Monitor memory
free -m

# Check disk I/O
iostat -x 1
```

## Performance Issues

### 1. High CPU Usage
```bash
# Check process
ps aux | grep python3

# Check logs
sudo tail -f /var/log/baselfirewall/performance.log

# Adjust scan intervals
sudo python3 -c "from firewall.ids_ips import adjust_scan_interval; adjust_scan_interval(5)"
```

### 2. Memory Issues
```bash
# Check memory usage
free -m

# Check swap
swapon -s

# Check process memory
pmap $(pgrep -f "python3.*firewall")
```

### 3. Disk Space
```bash
# Check log size
du -sh /var/log/baselfirewall/

# Check disk space
df -h

# Rotate logs
sudo logrotate -f /etc/logrotate.d/baselfirewall
```

## Network Issues

### 1. Rule Problems
```bash
# Check iptables rules
sudo iptables -L -n -v

# Check rule order
sudo iptables -L INPUT -n -v --line-numbers

# Reset rules
sudo python3 -c "from firewall.rules import reset_rules; reset_rules()"
```

### 2. Connection Issues
```bash
# Check network interfaces
ip addr show

# Check routing
ip route show

# Check connections
netstat -tuln
```

### 3. Protocol Issues
```bash
# Check protocol rules
sudo iptables -L INPUT -n -v | grep -i tcp
sudo iptables -L INPUT -n -v | grep -i udp

# Check service ports
sudo netstat -tuln | grep LISTEN
```

## Log Analysis

### 1. Log Review
```bash
# Check firewall logs
sudo tail -f /var/log/baselfirewall/firewall.log

# Check alert logs
sudo tail -f /var/log/baselfirewall/alerts.log

# Check system logs
sudo journalctl -u baselfirewall.service
```

### 2. Log Patterns
```bash
# Find common patterns
sudo grep "DROP" /var/log/baselfirewall/firewall.log | sort | uniq -c | sort -nr

# Check specific IP
sudo grep "192.168.1.100" /var/log/baselfirewall/firewall.log

# Check time patterns
sudo awk '{print $1}' /var/log/baselfirewall/firewall.log | cut -d: -f1 | sort | uniq -c
```

### 3. Log Rotation
```bash
# Check rotation config
sudo cat /etc/logrotate.d/baselfirewall

# Force rotation
sudo logrotate -f /etc/logrotate.d/baselfirewall

# Check rotated logs
ls -la /var/log/baselfirewall/
```

## Recovery Procedures

### 1. Complete Reset
```bash
# Stop service
sudo systemctl stop baselfirewall.service

# Reset rules
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Reset configuration
sudo python3 -c "from firewall.setup import reset_to_default; reset_to_default()"

# Start service
sudo systemctl start baselfirewall.service
```

### 2. Partial Reset
```bash
# Reset specific component
sudo python3 -c "from firewall.setup import reset_component; reset_component('ids_ips')"

# Reset rules only
sudo python3 -c "from firewall.rules import reset_rules; reset_rules()"

# Reset logging
sudo python3 -c "from firewall.setup import reset_logging; reset_logging()"
```

### 3. Backup and Restore
```bash
# Create backup
sudo python3 -c "from firewall.setup import create_backup; create_backup()"

# List backups
sudo python3 -c "from firewall.setup import list_backups; list_backups()"

# Restore backup
sudo python3 -c "from firewall.setup import restore_backup; restore_backup('backup_name')"
```

## Support Information

### 1. Debug Mode
```bash
# Enable debug logging
sudo python3 -c "from firewall.setup import enable_debug; enable_debug()"

# Check debug logs
sudo tail -f /var/log/baselfirewall/debug.log

# Disable debug
sudo python3 -c "from firewall.setup import disable_debug; disable_debug()"
```

### 2. System Information
```bash
# Collect system info
sudo python3 -c "from firewall.setup import collect_system_info; collect_system_info()"

# Check dependencies
sudo python3 -c "from firewall.setup import check_dependencies; check_dependencies()"

# Verify installation
sudo python3 -c "from firewall.setup import verify_installation; verify_installation()"
```

### 3. Contact Support
- GitHub Issues: [Repository Issues]
- Email: support@baselfirewall.com
- Documentation: [Documentation Link]
- Community Forum: [Forum Link]

--- 