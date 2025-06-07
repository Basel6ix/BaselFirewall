# BaselFirewall Configuration Validation Guide

## Table of Contents
1. [Validation Process](#validation-process)
2. [Configuration Checks](#configuration-checks)
3. [Rule Validation](#rule-validation)
4. [Performance Validation](#performance-validation)
5. [Security Validation](#security-validation)
6. [Troubleshooting](#troubleshooting)

## Validation Process

### 1. Configuration File Validation
```bash
# Validate JSON syntax
python3 -m json.tool config/firewall_config.json

# Check configuration structure
python3 -c "from firewall.config import validate_config; validate_config()"
```

### 2. Service Status Check
```bash
# Check service status
sudo systemctl status baselfirewall.service

# Check service logs
sudo journalctl -u baselfirewall.service -n 50
```

### 3. Interface Validation
```bash
# List configured interfaces
ip link show

# Verify interface configuration
python3 -c "from firewall.network import validate_interfaces; validate_interfaces()"
```

## Configuration Checks

### 1. Basic Configuration
```python
def validate_basic_config():
    required_fields = [
        "firewall.enabled",
        "firewall.default_policy",
        "firewall.interfaces",
        "logging.enabled",
        "logging.level"
    ]
    
    for field in required_fields:
        if not config.get(field):
            raise ValueError(f"Missing required field: {field}")
```

### 2. Network Configuration
```python
def validate_network_config():
    # Check interface existence
    for interface in config["interfaces"]:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface {interface} does not exist")
    
    # Validate IP addresses
    for network in config["networks"]:
        try:
            ipaddress.ip_network(network["subnet"])
        except ValueError:
            raise ValueError(f"Invalid subnet: {network['subnet']}")
```

### 3. IDS/IPS Configuration
```python
def validate_ids_ips_config():
    if config["ids_ips"]["enabled"]:
        # Check required tools
        required_tools = ["tcpdump", "nmap"]
        for tool in required_tools:
            if not shutil.which(tool):
                raise ValueError(f"Required tool not found: {tool}")
        
        # Validate thresholds
        if config["ids_ips"]["alert_threshold"] < 1:
            raise ValueError("Alert threshold must be positive")
```

## Rule Validation

### 1. Rule Syntax Check
```python
def validate_rules():
    valid_actions = ["ACCEPT", "DROP", "REJECT"]
    valid_protocols = ["tcp", "udp", "icmp", "any"]
    
    for rule in config["rules"]:
        # Check action
        if rule["action"] not in valid_actions:
            raise ValueError(f"Invalid action: {rule['action']}")
        
        # Check protocol
        if rule["protocol"] not in valid_protocols:
            raise ValueError(f"Invalid protocol: {rule['protocol']}")
        
        # Validate ports
        if "ports" in rule:
            for port in rule["ports"]:
                if not (0 <= port <= 65535):
                    raise ValueError(f"Invalid port: {port}")
```

### 2. Rule Conflict Check
```python
def check_rule_conflicts():
    # Check for overlapping rules
    for i, rule1 in enumerate(config["rules"]):
        for j, rule2 in enumerate(config["rules"][i+1:]):
            if rules_overlap(rule1, rule2):
                raise ValueError(f"Conflicting rules found: {rule1} and {rule2}")
```

### 3. Rule Application Test
```python
def test_rule_application():
    # Test rule application
    for rule in config["rules"]:
        try:
            apply_rule(rule)
        except Exception as e:
            raise ValueError(f"Failed to apply rule: {rule}, Error: {e}")
```

## Performance Validation

### 1. Resource Usage Check
```python
def validate_resource_limits():
    # Check CPU limit
    if config["performance"]["limits"]["cpu_percent"] > 100:
        raise ValueError("CPU limit cannot exceed 100%")
    
    # Check memory limit
    if config["performance"]["limits"]["memory_mb"] > get_system_memory():
        raise ValueError("Memory limit exceeds system memory")
```

### 2. Connection Limit Test
```python
def test_connection_limits():
    max_conn = config["performance"]["limits"]["max_connections"]
    current_conn = get_current_connections()
    
    if current_conn > max_conn:
        raise ValueError(f"Current connections ({current_conn}) exceed limit ({max_conn})")
```

### 3. Cache Performance Test
```python
def test_cache_performance():
    if config["performance"]["cache"]["enabled"]:
        # Test cache operations
        test_cache_operations()
        
        # Check cache size
        if get_cache_size() > config["performance"]["cache"]["max_size"]:
            raise ValueError("Cache size exceeds limit")
```

## Security Validation

### 1. Access Control Check
```python
def validate_access_control():
    # Check admin IPs
    for ip in config["security"]["access_control"]["admin_ips"]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid admin IP: {ip}")
    
    # Check SSL configuration
    if config["security"]["access_control"]["ssl"]["enabled"]:
        validate_ssl_config()
```

### 2. Update Configuration Check
```python
def validate_update_config():
    if config["security"]["updates"]["auto_update"]["enabled"]:
        # Check update interval
        if config["security"]["updates"]["auto_update"]["check_interval"] < 3600:
            raise ValueError("Update check interval too short")
        
        # Validate update time
        try:
            datetime.strptime(config["security"]["updates"]["auto_update"]["update_time"], "%H:%M")
        except ValueError:
            raise ValueError("Invalid update time format")
```

### 3. Security Policy Check
```python
def validate_security_policy():
    # Check default policy
    if config["firewall"]["default_policy"] == "ACCEPT":
        raise ValueError("Default policy should not be ACCEPT")
    
    # Check logging
    if not config["logging"]["enabled"]:
        raise ValueError("Logging should be enabled")
```

## Troubleshooting

### 1. Common Issues
- Configuration file not found
- Invalid JSON syntax
- Missing required fields
- Invalid IP addresses
- Rule conflicts
- Resource limits exceeded

### 2. Validation Commands
```bash
# Validate entire configuration
python3 -c "from firewall.config import validate_all; validate_all()"

# Check specific component
python3 -c "from firewall.config import validate_component; validate_component('ids_ips')"

# Test rule application
python3 -c "from firewall.rules import test_rules; test_rules()"
```

### 3. Log Analysis
```bash
# Check validation logs
sudo tail -f /var/log/baselfirewall/validation.log

# Analyze validation errors
python3 -c "from firewall.logs import analyze_validation_errors; analyze_validation_errors()"
```

## Best Practices

1. Always validate configuration before applying
2. Test rules in a staging environment
3. Monitor resource usage during validation
4. Keep validation logs for troubleshooting
5. Regular security policy reviews
6. Document all configuration changes
7. Backup configuration before changes
8. Use version control for configurations

--- 