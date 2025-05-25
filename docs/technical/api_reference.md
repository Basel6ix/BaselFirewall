# API Reference

## Overview
BaselFirewall provides both a Python API and a REST API for programmatic control and integration. This document details all available APIs, their usage, and examples.

## Python API

### Core Module

#### Firewall
```python
from baselfirewall import Firewall

# Initialize firewall
fw = Firewall()

# Start firewall
fw.start()

# Stop firewall
fw.stop()

# Reload configuration
fw.reload()

# Get status
status = fw.status()
```

#### Rule Management
```python
from baselfirewall import Rule, RuleManager

# Create rule
rule = Rule(
    action="ACCEPT",
    source="192.168.1.0/24",
    destination="any",
    protocol="tcp",
    port=80
)

# Add rule
manager = RuleManager()
manager.add_rule(rule)

# List rules
rules = manager.list_rules()

# Delete rule
manager.delete_rule(rule.id)
```

#### Security Module
```python
from baselfirewall import Security

# Initialize security
sec = Security()

# Configure IDS
sec.ids.enable()
sec.ids.set_sensitivity("high")

# Configure DoS protection
sec.dos.enable()
sec.dos.set_rate_limit(100)

# Configure NAT
sec.nat.add_forward(80, "192.168.1.100", 8080)
```

### User Management

#### Authentication
```python
from baselfirewall import Auth

# Initialize auth
auth = Auth()

# Create user
auth.create_user("username", "password", role="admin")

# Verify credentials
if auth.verify("username", "password"):
    print("Authentication successful")

# Delete user
auth.delete_user("username")
```

#### Role Management
```python
from baselfirewall import RoleManager

# Initialize manager
roles = RoleManager()

# Create role
roles.create("custom_role")

# Add permissions
roles.add_permission("custom_role", "security.view")

# Assign role
roles.assign_user("username", "custom_role")
```

### Logging

#### Log Management
```python
from baselfirewall import Logger

# Initialize logger
log = Logger()

# Write log
log.info("System started")
log.error("Connection failed")

# Query logs
entries = log.query(
    start_time="2024-01-01",
    end_time="2024-01-02",
    level="ERROR"
)

# Export logs
log.export("output.log")
```

## REST API

### Authentication

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": "password123"
}

Response:
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "expires_in": 3600
}
```

#### Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer <token>

Response:
{
    "message": "Logged out successfully"
}
```

### Firewall Rules

#### List Rules
```http
GET /api/v1/rules
Authorization: Bearer <token>

Response:
{
    "rules": [
        {
            "id": 1,
            "action": "ACCEPT",
            "source": "192.168.1.0/24",
            "destination": "any",
            "protocol": "tcp",
            "port": 80
        }
    ]
}
```

#### Add Rule
```http
POST /api/v1/rules
Authorization: Bearer <token>
Content-Type: application/json

{
    "action": "ACCEPT",
    "source": "192.168.1.0/24",
    "destination": "any",
    "protocol": "tcp",
    "port": 80
}

Response:
{
    "id": 1,
    "message": "Rule added successfully"
}
```

#### Delete Rule
```http
DELETE /api/v1/rules/{rule_id}
Authorization: Bearer <token>

Response:
{
    "message": "Rule deleted successfully"
}
```

### Security Features

#### IDS Configuration
```http
PUT /api/v1/security/ids
Authorization: Bearer <token>
Content-Type: application/json

{
    "enabled": true,
    "sensitivity": "high"
}

Response:
{
    "message": "IDS configured successfully"
}
```

#### DoS Protection
```http
PUT /api/v1/security/dos
Authorization: Bearer <token>
Content-Type: application/json

{
    "enabled": true,
    "rate_limit": 100,
    "connection_limit": 1000
}

Response:
{
    "message": "DoS protection configured successfully"
}
```

### User Management

#### Create User
```http
POST /api/v1/users
Authorization: Bearer <token>
Content-Type: application/json

{
    "username": "newuser",
    "password": "password123",
    "role": "standard"
}

Response:
{
    "id": 1,
    "message": "User created successfully"
}
```

#### Update User
```http
PUT /api/v1/users/{user_id}
Authorization: Bearer <token>
Content-Type: application/json

{
    "role": "admin",
    "email": "user@example.com"
}

Response:
{
    "message": "User updated successfully"
}
```

### System Management

#### System Status
```http
GET /api/v1/system/status
Authorization: Bearer <token>

Response:
{
    "status": "running",
    "uptime": 3600,
    "version": "1.0.0",
    "connections": 100
}
```

#### Configuration
```http
GET /api/v1/system/config
Authorization: Bearer <token>

Response:
{
    "config": {
        "log_level": "INFO",
        "max_connections": 1000,
        "session_timeout": 3600
    }
}
```

## Error Handling

### Error Codes
```python
ERROR_CODES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error"
}
```

### Error Response
```json
{
    "error": {
        "code": 400,
        "message": "Invalid request parameters",
        "details": {
            "field": "port",
            "reason": "Must be between 1 and 65535"
        }
    }
}
```

## Rate Limiting

### Limits
- Authentication: 5 requests per minute
- API calls: 100 requests per minute
- System operations: 20 requests per minute

### Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1577836800
```

## Versioning
- Current version: v1
- Version format: v{major}
- Version header: X-API-Version 