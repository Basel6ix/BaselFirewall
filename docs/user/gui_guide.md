# GUI Guide

## Overview
The BaselFirewall GUI provides an intuitive interface for managing your firewall. This guide covers all major features and operations available through the graphical interface.

## Launching the GUI
```bash
sudo python3 -m baselfirewall.gui
```

## Login Screen
- Username field
- Password field
- Login button
- Reset password link
- Version information

## Main Interface

### Navigation
- Firewall Rules tab
- Security Features tab
- Monitoring tab
- User Management tab
- Settings tab
- Help/About

### Toolbar
- Save changes
- Reload configuration
- Export settings
- Import settings
- Quick actions

## Firewall Rules

### Rule Management
1. Adding Rules:
   - Click "Add Rule" button
   - Select rule type
   - Configure parameters
   - Set priority
   - Enable/disable rule

2. Editing Rules:
   - Select rule from list
   - Modify parameters
   - Save changes

3. Deleting Rules:
   - Select rule
   - Click "Delete" button
   - Confirm deletion

### Rule Types
- Allow/Block IP
- Port rules
- Protocol rules
- Custom rules
- Time-based rules

## Security Features

### IDS/IPS
- Enable/disable
- Sensitivity settings
- Rule management
- Alert configuration
- Log viewing

### DoS Protection
- Enable/disable
- Rate limiting
- Connection limits
- Blacklist management
- Whitelist management

### NAT Configuration
- Port forwarding
- IP masquerading
- DMZ settings
- Custom NAT rules

## Monitoring

### Dashboard
- System status
- Traffic graphs
- Active connections
- Recent events
- Resource usage

### Logs
- Security logs
- System logs
- Access logs
- Error logs
- Custom logs

### Alerts
- Real-time alerts
- Alert history
- Alert configuration
- Notification settings

## User Management

### User Operations
- Add user
- Edit user
- Delete user
- Reset password
- Lock/unlock account

### Role Management
- Create role
- Edit permissions
- Assign users
- Remove roles

## Settings

### System Settings
- Language
- Theme
- Notifications
- Backup/restore
- Updates

### Network Settings
- Interface configuration
- DNS settings
- Proxy settings
- VPN integration

### Security Settings
- Password policy
- Session timeout
- Login attempts
- Two-factor auth

## Keyboard Shortcuts
| Action | Shortcut |
|--------|----------|
| Save | Ctrl+S |
| Reload | Ctrl+R |
| New Rule | Ctrl+N |
| Delete | Del |
| Help | F1 |
| Search | Ctrl+F |

## Best Practices
1. Regular backups
2. Test rules before applying
3. Document changes
4. Monitor logs
5. Review alerts

## Troubleshooting
1. GUI won't start
2. Login issues
3. Rule conflicts
4. Performance problems
5. Display issues

## Next Steps
- [Security Features](security_features.md)
- [User Management](user_management.md)
- [Technical Documentation](../technical/) 