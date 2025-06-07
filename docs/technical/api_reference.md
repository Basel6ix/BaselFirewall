# BaselFirewall API Reference

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

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