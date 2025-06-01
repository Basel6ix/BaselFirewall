# Security Features Guide

This guide details the security features available in BaselFirewall and how to configure them effectively.

## Core Security Features

### 1. Packet Filtering

BaselFirewall provides advanced packet filtering capabilities:

- **IP-based Filtering**
  ```bash
  # Allow specific IP
  sudo python main.py --allow-ip 192.168.1.100
  
  # Block specific IP
  sudo python main.py --block-ip 10.0.0.5
  ```

- **Port-based Filtering**
  ```bash
  # Block specific port
  sudo python main.py --block-port 22
  
  # Allow specific port
  sudo python main.py --allow-port 80
  ```

### 2. Intrusion Detection System (IDS)

The IDS monitors network traffic for suspicious activity:

- Real-time packet inspection
- Pattern-based attack detection
- Customizable detection rules
- Alert generation for suspicious activity

Configuration:
```bash
# Enable IDS
sudo python main.py --enable-ids

# Set custom threshold
sudo python main.py --set-ids-threshold 100

# View IDS logs
sudo python main.py --view-ids-logs
```

### 3. DoS Protection

Protection against Denial of Service attacks:

- SYN flood protection
- ICMP flood protection
- Connection rate limiting
- IP blacklisting for attackers

Settings:
```bash
# Enable DoS protection
sudo python main.py --enable-dos-protection

# Configure rate limits
sudo python main.py --set-rate-limit 50
```

### 4. Stateful Inspection

Intelligent packet filtering based on connection state:

- Tracks connection states
- Allows related traffic
- Blocks invalid packets
- Maintains connection table

Enable/Disable:
```bash
# Enable stateful inspection
sudo python main.py --enable-stateful

# Disable stateful inspection
sudo python main.py --disable-stateful
```

### 5. Network Address Translation (NAT)

NAT functionality for network security:

- Source NAT for outgoing traffic
- Destination NAT for incoming traffic
- Port forwarding capabilities
- NAT logging and tracking

Configuration:
```bash
# Enable NAT
sudo python main.py --enable-nat

# Configure NAT settings
sudo python main.py --set-nat-interface eth0
```

## Authentication & Access Control

### 1. User Management

- Role-based access control (admin/user)
- Secure password storage using bcrypt
- Password policy enforcement
- Session management

User operations:
```bash
# Add new user
sudo python register_user.py

# Change password
sudo python manage_users.py
```

### 2. Login Security

- Rate limiting for login attempts
- IP-based blocking after failed attempts
- Session timeout settings
- Secure session handling

## Logging & Monitoring

### 1. Event Logging

BaselFirewall maintains detailed logs of:

- Security events
- Connection attempts
- Rule matches
- System status
- User actions

View logs:
```bash
# View all logs
sudo python main.py --view-logs

# View security alerts
sudo python main.py --view-alerts

# Export logs
sudo python main.py --export-logs output.txt
```

### 2. Real-time Monitoring

Monitor system activity:
```bash
# Start monitoring
sudo python main.py --monitor

# View live connections
sudo python main.py --connections

# View blocked IPs
sudo python main.py --show-blocked
```

## Best Practices

1. **Regular Updates**
   - Keep BaselFirewall updated
   - Update system packages
   - Review and update rules regularly

2. **Configuration Security**
   - Use strong passwords
   - Limit admin access
   - Backup configurations
   - Review logs regularly

3. **Network Security**
   - Start with restrictive rules
   - Monitor for false positives
   - Test rule changes
   - Document configuration changes

4. **Performance Optimization**
   - Regular log rotation
   - Optimize rule ordering
   - Monitor system resources
   - Clean old connections

## Troubleshooting

### Common Issues

1. **High CPU Usage**
   - Check logging level
   - Review rule complexity
   - Monitor connection table size

2. **False Positives**
   - Adjust IDS sensitivity
   - Review blocked IPs
   - Check rule conflicts

3. **Connection Issues**
   - Verify rule ordering
   - Check NAT configuration
   - Review blocked ports

## Support

For additional assistance:
- Check the [FAQ](../FAQ.md)
- Review [Troubleshooting Guide](../TROUBLESHOOTING.md)
- Submit issues on GitHub
- Contact support team 