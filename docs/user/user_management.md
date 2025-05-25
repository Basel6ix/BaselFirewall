# User Management Guide

## Overview
BaselFirewall provides comprehensive user management capabilities to control access and permissions. This guide covers all aspects of user management, from basic operations to advanced role-based access control.

## User Types

### Administrator
- Full system access
- User management
- System configuration
- Security policy
- Audit capabilities

### Security Officer
- Security policy
- Rule management
- Alert handling
- Log analysis
- Report generation

### Network Manager
- Network configuration
- NAT management
- Interface settings
- Traffic monitoring
- Performance tuning

### Standard User
- View status
- Basic configuration
- Personal settings
- View logs
- Generate reports

## User Operations

### Creating Users
```bash
# Create admin user
sudo baselfirewall-cli user add --username admin --role administrator

# Create standard user
sudo baselfirewall-cli user add --username user1 --role standard
```

### Modifying Users
```bash
# Change password
sudo baselfirewall-cli user passwd username

# Change role
sudo baselfirewall-cli user role username new_role

# Update details
sudo baselfirewall-cli user update username --email new@email.com
```

### Deleting Users
```bash
# Delete user
sudo baselfirewall-cli user delete username

# Delete with cleanup
sudo baselfirewall-cli user delete username --cleanup
```

## Role Management

### Default Roles
1. Administrator
   - All permissions
   - System management
   - User management

2. Security Officer
   - Security configuration
   - Alert management
   - Log analysis

3. Network Manager
   - Network configuration
   - Performance monitoring
   - Basic security

4. Standard User
   - View access
   - Basic operations
   - Personal settings

### Custom Roles
```bash
# Create role
sudo baselfirewall-cli role create custom_role

# Add permissions
sudo baselfirewall-cli role permission custom_role add "security.view"
sudo baselfirewall-cli role permission custom_role add "logs.view"

# Assign role
sudo baselfirewall-cli user role username custom_role
```

## Permissions

### Permission Categories
1. Security
   - security.view
   - security.edit
   - security.admin

2. Network
   - network.view
   - network.edit
   - network.admin

3. System
   - system.view
   - system.edit
   - system.admin

4. Users
   - users.view
   - users.edit
   - users.admin

### Managing Permissions
```bash
# List permissions
sudo baselfirewall-cli permission list

# Add permission
sudo baselfirewall-cli permission add custom.permission

# Remove permission
sudo baselfirewall-cli permission remove custom.permission
```

## Access Control

### Authentication
- Password policy
- Two-factor authentication
- Session management
- Login attempts
- Password reset

### Authorization
- Role-based access
- Permission inheritance
- Access levels
- Resource restrictions
- Time-based access

## Session Management

### Configuration
```bash
# Set session timeout
sudo baselfirewall-cli config session timeout 3600

# Set max sessions
sudo baselfirewall-cli config session max 3

# Enable session logging
sudo baselfirewall-cli config session log true
```

### Monitoring
```bash
# List active sessions
sudo baselfirewall-cli session list

# Kill session
sudo baselfirewall-cli session kill session_id

# Kill all sessions
sudo baselfirewall-cli session killall
```

## Audit and Logging

### User Activity
- Login attempts
- Configuration changes
- Permission changes
- Resource access
- Command execution

### Log Management
```bash
# View user logs
sudo baselfirewall-cli log user username

# Export audit log
sudo baselfirewall-cli log export audit user.log

# Clear old logs
sudo baselfirewall-cli log clear --older-than 30d
```

## Best Practices

### Security
1. Strong passwords
2. Regular rotation
3. Least privilege
4. Activity monitoring
5. Regular audits

### Administration
1. Document procedures
2. Regular reviews
3. Backup user data
4. Test changes
5. Monitor usage

### Compliance
1. Access policies
2. Audit trails
3. Documentation
4. Regular training
5. Policy updates

## Troubleshooting

### Common Issues
1. Login problems
2. Permission errors
3. Session issues
4. Role conflicts
5. Authentication failures

### Diagnostics
```bash
# Check user status
sudo baselfirewall-cli user status username

# Verify permissions
sudo baselfirewall-cli user check username permission

# Test authentication
sudo baselfirewall-cli user test username
```

## Next Steps
- [Security Features](security_features.md)
- [Technical Documentation](../technical/)
- [API Reference](../technical/api_reference.md) 