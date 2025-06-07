# BaselFirewall Configuration Files Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

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