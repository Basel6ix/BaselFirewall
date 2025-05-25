# BaselFirewall Screenshots Guide

This directory contains organized screenshots for the BaselFirewall project demonstration. Each subdirectory corresponds to a specific section of the demo script.

## Directory Structure

### 1. initial_setup/
Required screenshots:
- Installation process completion screen
- Successful git clone output
- Setup.py installation completion
- Service status showing "active" state
- Initial system health check

### 2. gui_demo/
Required screenshots:
- Login screen with username/password fields
- Main dashboard showing all available tabs
- Firewall Rules tab interface
- "Add Allowed IP" dialog with example IP (192.168.1.100)
- "Block Port" interface with port 80 example
- List of currently blocked ports
- Features tab overview

### 3. ids_ips/
Required screenshots:
- IDS/IPS configuration panel with sensitivity settings
- Real-time log monitoring view
- SQL injection attack detection alert
- XSS attack prevention notification
- Security log entries showing detections
- IDS/IPS statistics dashboard

### 4. dos_protection/
Required screenshots:
- DoS protection configuration interface
- Connection limits settings (100 connections, 50/sec)
- Active monitoring dashboard during attack simulation
- Connection blocking notification
- IP blacklist management interface
- DoS attack logs and statistics

### 5. user_management/
Required screenshots:
- User creation form with all fields
- User list showing multiple accounts
- Permission editing interface for "testuser"
- Role selection dropdown
- User profile view
- Access control matrix
- Login view with restricted access

### 6. security_features/
Required screenshots:
- Stateful inspection configuration panel
- Active connection tracking table
- NAT configuration interface
- Interface selection (eth0/eth1)
- Port forwarding rules interface
- Connection state table
- Security feature toggles

### 7. performance/
Required screenshots:
- System resource usage dashboard
- CPU and memory graphs
- Network throughput statistics
- Connection count metrics
- Performance optimization settings
- Resource monitoring alerts
- Health check results

### 8. logging/
Required screenshots:
- Main log viewer interface
- Log type selection (System/Security/Access)
- Log filtering options
- Search functionality
- Export settings dialog
- Real-time log monitoring
- Alert notification system

### 9. backup/
Required screenshots:
- Backup configuration interface
- Backup creation dialog
- Restore configuration screen
- Backup history/list
- Export/Import options
- Backup status indicators
- Recovery confirmation dialog

## Screenshot Guidelines

1. Resolution: Minimum 1920x1080
2. Format: PNG preferred
3. Naming convention: section_name_description.png (e.g., gui_demo_login.png)
4. Each screenshot should be clear and focused on the relevant feature
5. Include any error messages or success notifications when relevant
6. Ensure no sensitive information is visible
7. Use consistent theme/appearance settings across all screenshots

## Usage Instructions

1. Place screenshots in their respective directories
2. Maintain the naming convention for easy reference
3. Update this README if additional screenshots are added
4. Ensure all required screenshots are captured before presentation
5. Keep backup copies of all screenshots

## Notes

- Screenshots should be taken with actual data and configurations
- Ensure the GUI is properly sized and all elements are visible
- Capture both successful operations and error handling
- Include tooltips and help text where relevant
- Show both light and dark theme versions if applicable 