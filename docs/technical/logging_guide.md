# BaselFirewall Logging Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

## Overview
BaselFirewall implements a comprehensive logging system that captures firewall events, security alerts, and system performance metrics.

## Log Files

### Main Log Files
1. **Firewall Log**
   - Location: `/var/log/baselfirewall/firewall.log`
   - Contains: Packet filtering decisions, rule matches, and basic events

2. **IDS/IPS Log**
   - Location: `/var/log/baselfirewall/ids_ips.log`
   - Contains: Intrusion detection events and prevention actions

3. **Alert Log**
   - Location: `/var/log/baselfirewall/alerts.log`
   - Contains: Security alerts and critical events

4. **Performance Log**
   - Location: `/var/log/baselfirewall/performance.log`
   - Contains: System performance metrics and resource usage

## Log Formats

### Firewall Log Format
```
timestamp|interface|action|protocol|source_ip|source_port|dest_ip|dest_port|rule_id
```

Example:
```
2024-03-07 10:15:23|eth0|DROP|TCP|192.168.1.100|54321|10.0.0.1|80|RULE_001
```

### IDS/IPS Log Format
```
timestamp|alert_type|severity|source_ip|description|action_taken
```

Example:
```
2024-03-07 10:15:23|PORT_SCAN|HIGH|192.168.1.100|Multiple ports scanned|BLOCKED
```

### Alert Log Format
```
timestamp|alert_id|severity|component|message|details
```

Example:
```
2024-03-07 10:15:23|ALT_001|CRITICAL|IDS|SYN Flood Detected|{"packets": 1000, "duration": "5s"}
```

## Log Rotation

### Configuration
Log rotation is configured in `/etc/logrotate.d/baselfirewall`:

```
/var/log/baselfirewall/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload baselfirewall.service
    endscript
}
```

### Manual Rotation
```bash
# Force log rotation
sudo logrotate -f /etc/logrotate.d/baselfirewall
```

## Log Analysis

### Basic Commands
```bash
# View last 100 lines
sudo tail -n 100 /var/log/baselfirewall/firewall.log

# Follow logs in real-time
sudo tail -f /var/log/baselfirewall/firewall.log

# Search for specific IP
sudo grep "192.168.1.100" /var/log/baselfirewall/firewall.log

# Count dropped packets
sudo grep "DROP" /var/log/baselfirewall/firewall.log | wc -l
```

### Advanced Analysis
```bash
# Extract unique source IPs
sudo awk '{print $4}' /var/log/baselfirewall/firewall.log | sort | uniq

# Count events by hour
sudo awk '{print $1}' /var/log/baselfirewall/firewall.log | cut -d: -f1 | sort | uniq -c

# Find top blocked IPs
sudo grep "DROP" /var/log/baselfirewall/firewall.log | awk '{print $4}' | sort | uniq -c | sort -nr
```

## Alert Monitoring

### Real-time Monitoring
```bash
# Monitor all alerts
sudo tail -f /var/log/baselfirewall/alerts.log

# Monitor high severity alerts
sudo tail -f /var/log/baselfirewall/alerts.log | grep "HIGH\|CRITICAL"
```

### Alert Notifications
Configure email notifications in `config/firewall_config.json`:
```json
{
    "logging": {
        "email_alerts": {
            "enabled": true,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "sender": "firewall@example.com",
            "recipients": ["admin@example.com"]
        }
    }
}
```

## Log Security

### Access Control
- Log files are owned by root:root
- Permissions set to 640
- Access restricted to root and baselfirewall group

### Log Protection
1. Regular backups
2. Secure storage
3. Access monitoring
4. Integrity checking

## Best Practices

### Log Management
1. Regular review of logs
2. Automated analysis
3. Alert threshold tuning
4. Log retention policy
5. Regular cleanup

### Performance
1. Monitor log size
2. Implement rotation
3. Use compression
4. Regular maintenance

## Troubleshooting

### Common Issues
1. **Log File Growth**
   - Check rotation configuration
   - Verify cleanup jobs
   - Monitor disk space

2. **Missing Logs**
   - Verify permissions
   - Check service status
   - Review configuration

3. **Performance Impact**
   - Adjust log levels
   - Implement filtering
   - Optimize rotation

## Integration

### SIEM Integration
Logs can be forwarded to SIEM systems using:
- Syslog forwarding
- Log file monitoring
- API integration

### Monitoring Tools
Compatible with:
- ELK Stack
- Graylog
- Splunk
- Nagios

--- 