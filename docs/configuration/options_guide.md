# BaselFirewall Configuration Options Guide

## Table of Contents
1. [Firewall Options](#firewall-options)
2. [Network Options](#network-options)
3. [IDS/IPS Options](#idsips-options)
4. [Logging Options](#logging-options)
5. [Performance Options](#performance-options)
6. [Security Options](#security-options)

## Firewall Options

### Basic Settings
```json
{
    "firewall": {
        "enabled": true,        // Enable/disable the firewall
        "default_policy": "DROP", // Default policy for unmatched packets
        "interfaces": ["eth0"], // List of interfaces to monitor
        "logging": {
            "enabled": true,    // Enable/disable logging
            "level": "INFO"     // Log level (DEBUG, INFO, WARNING, ERROR)
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether the firewall is active. When disabled, all traffic is allowed.
- `default_policy`: Sets the default action for packets that don't match any rules. Options: "ACCEPT", "DROP", "REJECT".
- `interfaces`: List of network interfaces to monitor. Each interface must exist on the system.
- `logging.level`: Controls the verbosity of logs. Higher levels include lower level messages.

### Rule Options
```json
{
    "rules": {
        "input": [
            {
                "protocol": "tcp",     // Protocol (tcp, udp, icmp, any)
                "ports": [80, 443],    // Port numbers or ranges
                "source": "any",       // Source IP or network
                "action": "ACCEPT",    // Action to take
                "comment": "Web traffic" // Rule description
            }
        ]
    }
}
```

#### Explanation
- `protocol`: Network protocol to match. "any" matches all protocols.
- `ports`: List of ports or port ranges (e.g., "80-100").
- `source`: Source IP address, network, or "any" for all sources.
- `action`: What to do with matching packets ("ACCEPT", "DROP", "REJECT").
- `comment`: Human-readable description of the rule's purpose.

## Network Options

### Interface Configuration
```json
{
    "interfaces": {
        "eth0": {
            "enabled": true,           // Enable/disable interface
            "type": "external",        // Interface type
            "ip_forwarding": false,    // Enable/disable IP forwarding
            "monitoring": true         // Enable/disable monitoring
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether the interface is monitored by the firewall.
- `type`: Interface classification ("external", "internal", "dmz").
- `ip_forwarding`: Enables/disables IP forwarding for the interface.
- `monitoring`: Enables/disables traffic monitoring on the interface.

### Network Rules
```json
{
    "networks": {
        "internal": {
            "subnet": "192.168.1.0/24", // Network subnet
            "rules": {
                "input": [
                    {
                        "protocol": "any",
                        "source": "any",
                        "action": "ACCEPT"
                    }
                ]
            }
        }
    }
}
```

#### Explanation
- `subnet`: Network address and subnet mask in CIDR notation.
- `rules`: Specific rules for this network segment.
- `input`: Rules for incoming traffic to this network.

## IDS/IPS Options

### Basic IDS/IPS Settings
```json
{
    "ids_ips": {
        "enabled": true,              // Enable/disable IDS/IPS
        "interface": "eth0",          // Interface to monitor
        "alert_threshold": 5,         // Number of alerts before action
        "block_duration": 3600,       // Block duration in seconds
        "signatures": {
            "enabled": true,          // Enable/disable signatures
            "update_interval": 86400   // Signature update interval
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether IDS/IPS is active.
- `interface`: Network interface to monitor for attacks.
- `alert_threshold`: Number of alerts before taking action.
- `block_duration`: How long to block offending IPs.
- `update_interval`: How often to check for signature updates.

### Detection Rules
```json
{
    "ids_ips": {
        "detection": {
            "port_scan": {
                "enabled": true,      // Enable/disable detection
                "threshold": 10,      // Number of ports to trigger
                "time_window": 60,    // Time window in seconds
                "action": "BLOCK"     // Action to take
            }
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether this detection type is active.
- `threshold`: Number of events to trigger detection.
- `time_window`: Time period for threshold counting.
- `action`: What to do when detected ("ALERT", "BLOCK").

## Logging Options

### Basic Logging
```json
{
    "logging": {
        "enabled": true,             // Enable/disable logging
        "level": "INFO",             // Log level
        "file": "/var/log/firewall.log", // Log file path
        "rotation": {
            "enabled": true,         // Enable/disable rotation
            "max_size": "100M",      // Maximum file size
            "backup_count": 7        // Number of backup files
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether logging is active.
- `level`: Minimum severity level to log.
- `file`: Path to the log file.
- `rotation`: Controls log file rotation settings.

### Alert Logging
```json
{
    "logging": {
        "alerts": {
            "enabled": true,         // Enable/disable alert logging
            "level": "WARNING",      // Minimum alert level
            "email": {
                "enabled": true,     // Enable/disable email alerts
                "recipients": ["admin@example.com"],
                "smtp_server": "smtp.example.com",
                "smtp_port": 587
            }
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether alert logging is active.
- `level`: Minimum severity level for alerts.
- `email`: Email notification settings for alerts.

## Performance Options

### Resource Limits
```json
{
    "performance": {
        "limits": {
            "cpu_percent": 80,       // Maximum CPU usage
            "memory_mb": 512,        // Maximum memory usage
            "max_connections": 10000, // Maximum concurrent connections
            "max_rules": 1000        // Maximum number of rules
        }
    }
}
```

#### Explanation
- `cpu_percent`: Maximum CPU usage percentage.
- `memory_mb`: Maximum memory usage in megabytes.
- `max_connections`: Maximum number of concurrent connections.
- `max_rules`: Maximum number of firewall rules.

### Cache Settings
```json
{
    "performance": {
        "cache": {
            "enabled": true,         // Enable/disable caching
            "max_size": 1000,        // Maximum cache entries
            "ttl": 3600,            // Time-to-live in seconds
            "cleanup_interval": 300  // Cleanup interval in seconds
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether caching is active.
- `max_size`: Maximum number of cache entries.
- `ttl`: How long entries remain in cache.
- `cleanup_interval`: How often to clean expired entries.

## Security Options

### Access Control
```json
{
    "security": {
        "access_control": {
            "admin_ips": ["192.168.1.100"], // Allowed admin IPs
            "api_key": "your-secret-key",   // API authentication key
            "ssl": {
                "enabled": true,            // Enable/disable SSL
                "cert_file": "/path/to/cert.pem",
                "key_file": "/path/to/key.pem"
            }
        }
    }
}
```

#### Explanation
- `admin_ips`: List of IPs allowed to access admin functions.
- `api_key`: Secret key for API authentication.
- `ssl`: SSL/TLS configuration for secure access.

### Update Settings
```json
{
    "security": {
        "updates": {
            "auto_update": {
                "enabled": true,     // Enable/disable auto-updates
                "check_interval": 86400, // Check interval in seconds
                "update_time": "03:00",  // Preferred update time
                "backup_before": true    // Backup before updating
            }
        }
    }
}
```

#### Explanation
- `enabled`: Controls whether automatic updates are active.
- `check_interval`: How often to check for updates.
- `update_time`: Preferred time for updates.
- `backup_before`: Whether to backup before updating.

--- 