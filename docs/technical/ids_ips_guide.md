# BaselFirewall IDS/IPS Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

## Overview
The Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) in BaselFirewall provides real-time network traffic monitoring and protection against various types of attacks.

## Features
- Real-time packet inspection
- Signature-based detection
- Anomaly detection
- Automatic blocking of malicious traffic
- Custom rule support
- Performance monitoring

## Configuration

### Basic Setup
```bash
# Enable IDS/IPS
sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"
```

### Configuration Options
The IDS/IPS can be configured through the `config/firewall_config.json` file:

```json
{
    "ids_ips": {
        "enabled": true,
        "interface": "eth0",
        "alert_threshold": 5,
        "block_duration": 3600,
        "signatures": {
            "enabled": true,
            "update_interval": 86400
        },
        "anomaly_detection": {
            "enabled": true,
            "threshold": 100
        }
    }
}
```

## Alert Types

### 1. Port Scan Detection
- Detects rapid port scanning attempts
- Configurable threshold for scan detection
- Automatic blocking of scanning IPs

### 2. DoS Attack Detection
- SYN flood detection
- ICMP flood detection
- UDP flood detection
- Rate-based blocking

### 3. Suspicious Traffic
- Unusual protocol usage
- Known attack patterns
- Custom rule violations

## Performance Considerations

### Resource Usage
- CPU: Moderate (5-15% during normal operation)
- Memory: ~50MB base + ~10MB per 1000 rules
- Disk: ~100MB for logs and signatures

### Optimization Tips
1. Adjust scan intervals for high-traffic networks
2. Use specific interface monitoring
3. Implement log rotation
4. Regular signature updates

## Monitoring

### Log Files
- Main log: `/var/log/baselfirewall/ids_ips.log`
- Alert log: `/var/log/baselfirewall/alerts.log`
- Performance log: `/var/log/baselfirewall/performance.log`

### Alert Monitoring
```bash
# View real-time alerts
sudo tail -f /var/log/baselfirewall/alerts.log

# View performance metrics
sudo tail -f /var/log/baselfirewall/performance.log
```

## Troubleshooting

### Common Issues
1. **High CPU Usage**
   - Check scan intervals
   - Review rule complexity
   - Monitor traffic patterns

2. **False Positives**
   - Adjust thresholds
   - Review custom rules
   - Update signatures

3. **Missed Alerts**
   - Verify interface configuration
   - Check log permissions
   - Review alert thresholds

### Debug Mode
Enable debug logging:
```bash
sudo python3 -c "from firewall.ids_ips import enable_debug; enable_debug()"
```

## Best Practices
1. Regular signature updates
2. Custom rule testing
3. Performance monitoring
4. Log analysis
5. Regular maintenance

## Integration
The IDS/IPS can be integrated with:
- SIEM systems
- Log management tools
- Monitoring systems
- Alert notification systems

## Security Considerations
1. Secure configuration storage
2. Regular updates
3. Access control
4. Log protection
5. Performance monitoring

--- 