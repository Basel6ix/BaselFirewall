# Configuration Files

## Overview
BaselFirewall uses a set of configuration files to manage its settings and behavior. This document details the structure and usage of these configuration files.

## File Locations

### Main Configuration
```
/etc/baselfirewall/
├── config.yaml          # Main configuration
├── rules/               # Firewall rules
│   ├── default.yaml     # Default rules
│   └── custom.yaml      # Custom rules
├── security/            # Security settings
│   ├── ids.yaml         # IDS/IPS configuration
│   └── dos.yaml         # DoS protection settings
├── users/               # User management
│   ├── users.yaml       # User database
│   └── roles.yaml       # Role definitions
└── logs/               # Log configuration
    └── logging.yaml     # Logging settings
```

## Configuration Format

### Main Configuration (config.yaml)
```yaml
# System Settings
system:
  hostname: baselfirewall
  version: 1.0.0
  language: en
  timezone: UTC

# Network Settings
network:
  interfaces:
    - name: eth0
      type: external
      address: dhcp
    - name: eth1
      type: internal
      address: 192.168.1.1/24

# Security Settings
security:
  ids_enabled: true
  dos_enabled: true
  nat_enabled: true
  state_tracking: true

# User Interface
ui:
  gui_enabled: true
  gui_port: 8080
  theme: dark
  session_timeout: 3600

# Logging
logging:
  level: INFO
  file: /var/log/baselfirewall/system.log
  max_size: 100M
  backup_count: 5
```

### Firewall Rules (rules/default.yaml)
```yaml
# Default Rules
rules:
  - name: allow_ssh
    action: ACCEPT
    protocol: tcp
    port: 22
    source: any
    destination: any
    enabled: true

  - name: allow_http
    action: ACCEPT
    protocol: tcp
    port: 80
    source: any
    destination: any
    enabled: true

  - name: block_telnet
    action: DROP
    protocol: tcp
    port: 23
    source: any
    destination: any
    enabled: true
```

### IDS Configuration (security/ids.yaml)
```yaml
# IDS/IPS Settings
ids:
  enabled: true
  mode: prevention
  sensitivity: high
  
  # Signature Database
  signatures:
    update_url: https://updates.baselfirewall.org/signatures
    update_interval: 86400
    
  # Detection Rules
  rules:
    - name: sql_injection
      pattern: "SELECT.*FROM"
      severity: high
      action: BLOCK
      
    - name: xss_attack
      pattern: "<script>.*</script>"
      severity: high
      action: BLOCK

  # Response Actions
  actions:
    block_duration: 3600
    alert_threshold: 5
    notification_email: admin@example.com
```

### DoS Protection (security/dos.yaml)
```yaml
# DoS Protection Settings
dos:
  enabled: true
  
  # Rate Limiting
  limits:
    connections_per_ip: 100
    packets_per_second: 1000
    bandwidth_mbps: 100
    
  # Blacklist
  blacklist:
    enabled: true
    threshold: 10
    duration: 3600
    
  # Whitelist
  whitelist:
    - 192.168.1.0/24
    - 10.0.0.0/8
```

### User Database (users/users.yaml)
```yaml
# User Definitions
users:
  - username: admin
    password_hash: "$2a$10$..."
    role: administrator
    email: admin@example.com
    enabled: true
    
  - username: security
    password_hash: "$2a$10$..."
    role: security_officer
    email: security@example.com
    enabled: true
```

### Role Definitions (users/roles.yaml)
```yaml
# Role Definitions
roles:
  administrator:
    permissions:
      - "*"
    
  security_officer:
    permissions:
      - security.view
      - security.edit
      - logs.view
      
  network_manager:
    permissions:
      - network.view
      - network.edit
      - logs.view
```

### Logging Configuration (logs/logging.yaml)
```yaml
# Logging Settings
logging:
  version: 1
  
  # Handlers
  handlers:
    file:
      class: logging.handlers.RotatingFileHandler
      filename: /var/log/baselfirewall/system.log
      maxBytes: 10485760
      backupCount: 5
      formatter: standard
      
    syslog:
      class: logging.handlers.SysLogHandler
      address: /dev/log
      facility: local0
      formatter: standard
      
  # Formatters
  formatters:
    standard:
      format: "%(asctime)s [%(levelname)s] %(message)s"
      datefmt: "%Y-%m-%d %H:%M:%S"
      
  # Loggers
  loggers:
    baselfirewall:
      level: INFO
      handlers: [file, syslog]
      propagate: false
```

## Configuration Management

### File Permissions
```bash
# Directory permissions
drwxr-x--- root baselfirewall /etc/baselfirewall/
drwxr-x--- root baselfirewall /etc/baselfirewall/rules/
drwxr-x--- root baselfirewall /etc/baselfirewall/security/
drwxr-x--- root baselfirewall /etc/baselfirewall/users/
drwxr-x--- root baselfirewall /etc/baselfirewall/logs/

# File permissions
-rw-r----- root baselfirewall /etc/baselfirewall/config.yaml
-rw-r----- root baselfirewall /etc/baselfirewall/rules/*.yaml
-rw-r----- root baselfirewall /etc/baselfirewall/security/*.yaml
-rw-r----- root baselfirewall /etc/baselfirewall/users/*.yaml
-rw-r----- root baselfirewall /etc/baselfirewall/logs/*.yaml
```

### Backup and Restore
```bash
# Backup configuration
sudo baselfirewall-cli config backup

# Restore configuration
sudo baselfirewall-cli config restore backup.tar.gz

# Export configuration
sudo baselfirewall-cli config export config.yaml

# Import configuration
sudo baselfirewall-cli config import config.yaml
```

### Version Control
```bash
# Show config version
sudo baselfirewall-cli config version

# List changes
sudo baselfirewall-cli config history

# Rollback changes
sudo baselfirewall-cli config rollback
```

## Best Practices

### Security
1. Regular backups
2. Version control
3. Access control
4. Encryption
5. Validation

### Maintenance
1. Regular updates
2. Clean unused rules
3. Document changes
4. Test changes
5. Monitor logs

### Performance
1. Optimize rules
2. Clean old logs
3. Regular cleanup
4. Monitor size
5. Archive data 