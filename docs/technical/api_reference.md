# API Reference

This document provides detailed information about BaselFirewall's API endpoints and usage.

## Core Modules

### 1. Firewall Management

#### Rule Management

```python
from firewall.rules import RuleManager

# Initialize rule manager
rule_manager = RuleManager()

# Add IP-based rule
rule_manager.add_ip_rule(ip="192.168.1.100", action="allow")

# Add port-based rule
rule_manager.add_port_rule(port=80, action="block")

# Remove rule
rule_manager.remove_rule(rule_id="rule_123")
```

Available Methods:
- `add_ip_rule(ip: str, action: str) -> str`
- `add_port_rule(port: int, action: str) -> str`
- `remove_rule(rule_id: str) -> bool`
- `get_rules() -> List[Dict]`
- `clear_rules() -> bool`

### 2. IDS/IPS System

```python
from firewall.ids_ips import IDSManager

# Initialize IDS manager
ids_manager = IDSManager()

# Enable IDS
ids_manager.enable()

# Add custom rule
ids_manager.add_rule(
    pattern="HTTP_ATTACK",
    content="../",
    port=80,
    action="block"
)

# Get alerts
alerts = ids_manager.get_alerts()
```

Available Methods:
- `enable() -> bool`
- `disable() -> bool`
- `add_rule(pattern: str, content: str, port: int, action: str) -> str`
- `remove_rule(rule_id: str) -> bool`
- `get_alerts() -> List[Dict]`
- `set_sensitivity(level: str) -> bool`

### 3. DoS Protection

```python
from firewall.dos import DosProtection

# Initialize DoS protection
dos_protection = DosProtection()

# Enable protection
dos_protection.enable()

# Set rate limits
dos_protection.set_rate_limit(
    connections_per_second=100,
    burst=200
)

# Add to blacklist
dos_protection.add_to_blacklist("10.0.0.5")
```

Available Methods:
- `enable() -> bool`
- `disable() -> bool`
- `set_rate_limit(connections_per_second: int, burst: int) -> bool`
- `add_to_blacklist(ip: str) -> bool`
- `remove_from_blacklist(ip: str) -> bool`
- `get_blacklist() -> List[str]`

### 4. NAT Configuration

```python
from firewall.nat import NATManager

# Initialize NAT manager
nat_manager = NATManager()

# Enable NAT
nat_manager.enable()

# Add port forwarding
nat_manager.add_port_forward(
    external_port=80,
    internal_ip="192.168.1.100",
    internal_port=8080
)
```

Available Methods:
- `enable() -> bool`
- `disable() -> bool`
- `add_port_forward(external_port: int, internal_ip: str, internal_port: int) -> bool`
- `remove_port_forward(external_port: int) -> bool`
- `get_port_forwards() -> List[Dict]`

### 5. Authentication

```python
from firewall.auth import AuthManager

# Initialize auth manager
auth_manager = AuthManager()

# Register new user
auth_manager.register_user(
    username="admin",
    password="secure_password",
    role="admin"
)

# Authenticate user
token = auth_manager.authenticate(
    username="admin",
    password="secure_password"
)

# Verify token
is_valid = auth_manager.verify_token(token)
```

Available Methods:
- `register_user(username: str, password: str, role: str) -> bool`
- `authenticate(username: str, password: str) -> str`
- `verify_token(token: str) -> bool`
- `change_password(username: str, old_password: str, new_password: str) -> bool`
- `delete_user(username: str) -> bool`

### 6. Logging System

```python
from firewall.logging import LogManager

# Initialize log manager
log_manager = LogManager()

# Log security event
log_manager.log_security_event(
    event_type="INTRUSION_ATTEMPT",
    source_ip="10.0.0.5",
    details="SSH brute force attempt"
)

# Get security logs
logs = log_manager.get_security_logs(
    start_time="2024-01-01T00:00:00Z",
    end_time="2024-01-02T00:00:00Z"
)
```

Available Methods:
- `log_security_event(event_type: str, source_ip: str, details: str) -> bool`
- `log_system_event(event_type: str, details: str) -> bool`
- `get_security_logs(start_time: str, end_time: str) -> List[Dict]`
- `get_system_logs(start_time: str, end_time: str) -> List[Dict]`
- `clear_logs() -> bool`

## CLI Interface

The command-line interface provides access to all API functionality:

```bash
# Rule management
sudo python main.py --add-rule ip=192.168.1.100 action=allow
sudo python main.py --remove-rule rule_123

# IDS management
sudo python main.py --enable-ids
sudo python main.py --add-ids-rule pattern=HTTP_ATTACK

# DoS protection
sudo python main.py --enable-dos
sudo python main.py --set-rate-limit 100

# NAT configuration
sudo python main.py --enable-nat
sudo python main.py --add-port-forward 80:192.168.1.100:8080

# User management
sudo python main.py --add-user admin
sudo python main.py --change-password admin

# Log management
sudo python main.py --view-logs
sudo python main.py --export-logs output.txt
```

## GUI Interface

The GUI provides access to all API functionality through a user-friendly interface:

1. **Rule Management Tab**
   - Add/remove IP rules
   - Add/remove port rules
   - View active rules

2. **Security Tab**
   - Enable/disable IDS
   - Configure DoS protection
   - Manage blacklist

3. **NAT Tab**
   - Enable/disable NAT
   - Configure port forwarding
   - Set up DMZ

4. **Users Tab**
   - Manage users
   - Change passwords
   - View user activity

5. **Logs Tab**
   - View security logs
   - View system logs
   - Export logs

## Error Handling

All API methods return appropriate error codes and messages:

```python
from firewall.exceptions import (
    FirewallError,
    AuthenticationError,
    ConfigurationError
)

try:
    rule_manager.add_ip_rule(ip="invalid_ip", action="allow")
except FirewallError as e:
    print(f"Firewall error: {e}")
except AuthenticationError as e:
    print(f"Authentication error: {e}")
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

Common error codes:
- 1000: Invalid configuration
- 2000: Authentication failure
- 3000: Permission denied
- 4000: Resource not found
- 5000: Internal error

## Best Practices

1. **Error Handling**
   - Always wrap API calls in try-except blocks
   - Log errors appropriately
   - Provide user-friendly error messages

2. **Authentication**
   - Always verify user permissions
   - Use secure password storage
   - Implement token expiration

3. **Performance**
   - Cache frequently used data
   - Use batch operations when possible
   - Monitor resource usage

4. **Security**
   - Validate all input
   - Use HTTPS for remote access
   - Implement rate limiting

## Support

For API support:
- Check the [FAQ](../FAQ.md)
- Review [Troubleshooting Guide](../TROUBLESHOOTING.md)
- Submit issues on GitHub
- Contact the development team 