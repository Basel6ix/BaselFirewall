# BaselFirewall Configuration Examples

**Author:** B. Abu-Radaha  
**Supervisor:** M. Nabrawi  
**College:** Hittien College  
**Date:** May 2025

## Table of Contents
1. [Basic Configuration](#basic-configuration)
2. [Network Rules](#network-rules)
3. [IDS/IPS Configuration](#idsips-configuration)
4. [Logging Configuration](#logging-configuration)
5. [Performance Tuning](#performance-tuning)
6. [Advanced Scenarios](#advanced-scenarios)

## Basic Configuration

### 1. Default Configuration
```json
{
    "firewall": {
        "enabled": true,
        "default_policy": "DROP",
        "interfaces": ["eth0"],
        "logging": {
            "enabled": true,
            "level": "INFO"
        }
    }
}
```

### 2. Basic Service Rules
```json
{
    "rules": {
        "input": [
            {
                "protocol": "tcp",
                "ports": [22],
                "source": "any",
                "action": "ACCEPT",
                "comment": "Allow SSH"
            },
            {
                "protocol": "tcp",
                "ports": [80, 443],
                "source": "any",
                "action": "ACCEPT",
                "comment": "Allow HTTP/HTTPS"
            }
        ]
    }
}
```

### 3. Network Interface Configuration
```json
{
    "interfaces": {
        "eth0": {
            "enabled": true,
            "type": "external",
            "ip_forwarding": false,
            "monitoring": true
        },
        "eth1": {
            "enabled": true,
            "type": "internal",
            "ip_forwarding": true,
            "monitoring": true
        }
    }
}
```

## Network Rules

### 1. Port-Based Rules
```json
{
    "rules": {
        "input": [
            {
                "protocol": "tcp",
                "ports": [3306],
                "source": "192.168.1.0/24",
                "action": "ACCEPT",
                "comment": "Allow MySQL from internal network"
            },
            {
                "protocol": "udp",
                "ports": [53],
                "source": "any",
                "action": "ACCEPT",
                "comment": "Allow DNS"
            }
        ]
    }
}
```

### 2. IP-Based Rules
```json
{
    "rules": {
        "input": [
            {
                "protocol": "any",
                "source": "10.0.0.0/8",
                "action": "DROP",
                "comment": "Block private network"
            },
            {
                "protocol": "any",
                "source": "192.168.1.100",
                "action": "ACCEPT",
                "comment": "Allow specific IP"
            }
        ]
    }
}
```

### 3. Stateful Rules
```json
{
    "rules": {
        "input": [
            {
                "protocol": "tcp",
                "state": "ESTABLISHED,RELATED",
                "action": "ACCEPT",
                "comment": "Allow established connections"
            },
            {
                "protocol": "tcp",
                "state": "NEW",
                "ports": [80, 443],
                "action": "ACCEPT",
                "comment": "Allow new HTTP/HTTPS connections"
            }
        ]
    }
}
```

## IDS/IPS Configuration

### 1. Basic IDS/IPS Setup
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
        }
    }
}
```

### 2. Attack Detection Rules
```json
{
    "ids_ips": {
        "detection": {
            "port_scan": {
                "enabled": true,
                "threshold": 10,
                "time_window": 60,
                "action": "BLOCK"
            },
            "syn_flood": {
                "enabled": true,
                "threshold": 100,
                "time_window": 10,
                "action": "BLOCK"
            },
            "icmp_flood": {
                "enabled": true,
                "threshold": 50,
                "time_window": 5,
                "action": "BLOCK"
            }
        }
    }
}
```

### 3. Custom Signatures
```json
{
    "ids_ips": {
        "signatures": {
            "custom": [
                {
                    "name": "custom_attack",
                    "pattern": "\\x90\\x90\\x90",
                    "description": "Custom attack pattern",
                    "action": "ALERT"
                },
                {
                    "name": "suspicious_traffic",
                    "pattern": "GET /admin",
                    "description": "Admin access attempt",
                    "action": "BLOCK"
                }
            ]
        }
    }
}
```

## Logging Configuration

### 1. Basic Logging
```json
{
    "logging": {
        "enabled": true,
        "level": "INFO",
        "file": "/var/log/baselfirewall/firewall.log",
        "rotation": {
            "enabled": true,
            "max_size": "100M",
            "backup_count": 7
        }
    }
}
```

### 2. Alert Logging
```json
{
    "logging": {
        "alerts": {
            "enabled": true,
            "file": "/var/log/baselfirewall/alerts.log",
            "level": "WARNING",
            "email": {
                "enabled": true,
                "recipients": ["admin@example.com"],
                "smtp_server": "smtp.example.com",
                "smtp_port": 587
            }
        }
    }
}
```

### 3. Performance Logging
```json
{
    "logging": {
        "performance": {
            "enabled": true,
            "file": "/var/log/baselfirewall/performance.log",
            "metrics": ["cpu", "memory", "disk", "network"],
            "interval": 300
        }
    }
}
```

## Performance Tuning

### 1. Resource Limits
```json
{
    "performance": {
        "limits": {
            "cpu_percent": 80,
            "memory_mb": 512,
            "max_connections": 10000,
            "max_rules": 1000
        }
    }
}
```

### 2. Scan Intervals
```json
{
    "ids_ips": {
        "scanning": {
            "interval": 5,
            "batch_size": 1000,
            "timeout": 30,
            "max_threads": 4
        }
    }
}
```

### 3. Cache Configuration
```json
{
    "performance": {
        "cache": {
            "enabled": true,
            "max_size": 1000,
            "ttl": 3600,
            "cleanup_interval": 300
        }
    }
}
```

## Advanced Scenarios

### 1. Multi-Network Setup
```json
{
    "networks": {
        "dmz": {
            "interface": "eth1",
            "subnet": "192.168.1.0/24",
            "rules": {
                "input": [
                    {
                        "protocol": "tcp",
                        "ports": [80, 443],
                        "source": "any",
                        "action": "ACCEPT"
                    }
                ]
            }
        },
        "internal": {
            "interface": "eth2",
            "subnet": "10.0.0.0/24",
            "rules": {
                "input": [
                    {
                        "protocol": "any",
                        "source": "192.168.1.0/24",
                        "action": "ACCEPT"
                    }
                ]
            }
        }
    }
}
```

### 2. High Availability
```json
{
    "ha": {
        "enabled": true,
        "mode": "active-passive",
        "interface": "eth0",
        "vrrp": {
            "enabled": true,
            "group": 1,
            "priority": 100,
            "auth": {
                "type": "PASS",
                "password": "secret"
            }
        }
    }
}
```

### 3. Load Balancing
```json
{
    "load_balancing": {
        "enabled": true,
        "algorithm": "round-robin",
        "services": [
            {
                "name": "web",
                "protocol": "tcp",
                "port": 80,
                "backends": [
                    "192.168.1.10:80",
                    "192.168.1.11:80"
                ]
            }
        ]
    }
}
```

## Configuration Management

### 1. Version Control
```json
{
    "config_management": {
        "version_control": {
            "enabled": true,
            "backup_dir": "/etc/baselfirewall/backups",
            "max_backups": 10,
            "auto_backup": true
        }
    }
}
```

### 2. Automated Updates
```json
{
    "updates": {
        "auto_update": {
            "enabled": true,
            "check_interval": 86400,
            "update_time": "03:00",
            "backup_before": true
        }
    }
}
```

### 3. Monitoring Integration
```json
{
    "monitoring": {
        "prometheus": {
            "enabled": true,
            "port": 9090,
            "metrics": ["firewall", "ids_ips", "performance"]
        },
        "snmp": {
            "enabled": true,
            "community": "public",
            "trap_port": 162
        }
    }
}
```

## Best Practices

1. **Rule Organization**
   - Group related rules
   - Use descriptive comments
   - Regular rule review
   - Document rule purposes

2. **Security Considerations**
   - Default deny policy
   - Explicit allow rules
   - Regular updates
   - Log monitoring

3. **Performance Optimization**
   - Optimize rule order
   - Use connection tracking
   - Regular cleanup
   - Resource monitoring

--- 