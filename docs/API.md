# BaselFirewall API Documentation

## Core Modules

### 1. Firewall Rules (`firewall.rules`)

#### Functions

##### `allow_ip(ip: str) -> bool`
Add an IP address to the allowed list.
- **Parameters**: `ip` - IP address to allow
- **Returns**: `True` if successful, `False` otherwise

##### `block_ip(ip: str) -> bool`
Add an IP address to the blocked list.
- **Parameters**: `ip` - IP address to block
- **Returns**: `True` if successful, `False` otherwise

##### `block_port(port: int) -> bool`
Block a specific port.
- **Parameters**: `port` - Port number to block
- **Returns**: `True` if successful, `False` otherwise

##### `disable_firewall() -> bool`
Completely disable the firewall.
- **Returns**: `True` if successful, `False` otherwise

##### `enable_firewall() -> bool`
Re-enable the firewall with default configuration.
- **Returns**: `True` if successful, `False` otherwise

### 2. Authentication (`firewall.auth`)

##### `register_user(username: str, password: str, is_admin: bool) -> bool`
Register a new user.
- **Parameters**:
  - `username` - Username for the new account
  - `password` - Password for the new account
  - `is_admin` - Whether the user should have admin privileges
- **Returns**: `True` if successful, `False` otherwise

##### `authenticate(username: str, password: str) -> bool`
Authenticate a user.
- **Parameters**:
  - `username` - Username to authenticate
  - `password` - Password to verify
- **Returns**: `True` if authentication successful, `False` otherwise

### 3. NAT (`firewall.nat`)

##### `enable_nat() -> bool`
Enable NAT functionality.
- **Returns**: `True` if successful, `False` otherwise

##### `disable_nat() -> bool`
Disable NAT functionality.
- **Returns**: `True` if successful, `False` otherwise

##### `configure_nat(external_interface: str, internal_interface: str, internal_network: str) -> bool`
Configure NAT settings.
- **Parameters**:
  - `external_interface` - Name of external network interface
  - `internal_interface` - Name of internal network interface
  - `internal_network` - Internal network in CIDR notation
- **Returns**: `True` if successful, `False` otherwise

### 4. IDS/IPS (`firewall.ids_ips`)

##### `enable_ids_ips() -> bool`
Enable IDS/IPS functionality.
- **Returns**: `True` if successful, `False` otherwise

##### `disable_ids_ips() -> bool`
Disable IDS/IPS functionality.
- **Returns**: `True` if successful, `False` otherwise

### 5. DoS Protection (`firewall.dos`)

##### `enable_dos_protection() -> bool`
Enable DoS protection.
- **Returns**: `True` if successful, `False` otherwise

##### `disable_dos_protection() -> bool`
Disable DoS protection.
- **Returns**: `True` if successful, `False` otherwise

## Configuration Management

### 1. Config Manager (`firewall.config_manager`)

##### `load_config() -> dict`
Load configuration from file.
- **Returns**: Configuration dictionary

##### `save_config(config: dict) -> bool`
Save configuration to file.
- **Parameters**: `config` - Configuration dictionary to save
- **Returns**: `True` if successful, `False` otherwise

##### `reset_config() -> bool`
Reset configuration to defaults.
- **Returns**: `True` if successful, `False` otherwise

## User Interfaces

### 1. CLI Interface

The CLI interface is accessible through `main.py` by selecting option 1. It provides command-line access to all firewall functionality.

### 2. GUI Interface

The GUI interface is accessible through `main.py` by selecting option 2. It provides a graphical interface with tabs for:
- Firewall Rules Management
- Feature Controls
- Logs & Alerts
- User Management
- Configuration

## Error Handling

All API functions follow these error handling principles:
1. Return `False` or raise an exception on failure
2. Log errors using `log_event()`
3. Provide meaningful error messages
4. Handle permissions and authentication failures gracefully

## Configuration Files

### firewall_config.json
```json
{
    "allowed_ips": [],
    "blocked_ips": [],
    "blocked_ports": [],
    "firewall_enabled": true,
    "dos_protection_enabled": false,
    "ids_ips_enabled": false,
    "nat_enabled": false,
    "stateful_enabled": false,
    "nat_config": {
        "external_interface": "",
        "internal_interface": "",
        "internal_network": ""
    }
}
```

### users.json
```json
{
    "users": {}
}
``` 