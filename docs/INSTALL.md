# BaselFirewall Installation Guide

## System Requirements

### Operating System
- Linux (Debian/Ubuntu/Kali Linux recommended)
- Kernel version 4.x or higher
- Root/sudo access required

### Python Requirements
- Python 3.8 or higher
- pip package manager
- venv module

### Network Requirements
- Network interface card(s)
- Root access to modify iptables rules
- Network configuration permissions

## Installation Steps

### 1. System Preparation

```bash
# Update system packages
sudo apt update
sudo apt upgrade -y

# Install required system packages
sudo apt install -y python3-pip python3-venv iptables net-tools
```

### 2. Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-username/BaselFirewall.git
cd BaselFirewall
```

### 3. Virtual Environment Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Configuration Setup

```bash
# Create configuration directory if it doesn't exist
mkdir -p config

# Initialize configuration files
cp resources/example_configs/firewall_config.json config/
cp resources/example_configs/users.json config/
```

### 5. Permissions Setup

```bash
# Ensure proper permissions for log directory
sudo mkdir -p /var/log/baselfirewall
sudo chown -R $USER:$USER /var/log/baselfirewall

# Set proper permissions for configuration files
chmod 600 config/*.json
```

### 6. First Run and Initial Setup

```bash
# Run the firewall setup script
sudo python3 main.py
```

## Post-Installation Steps

### 1. Create Admin User
```bash
sudo python3 register_user.py
# Follow prompts to create admin account
```

### 2. Configure Network Interfaces
1. Open `config/firewall_config.json`
2. Set appropriate values for:
   - `external_interface`
   - `internal_interface`
   - `internal_network`

### 3. Test Installation
```bash
# Run test suite
sudo python3 -m pytest tests/
```

## Common Issues and Solutions

### 1. Permission Errors
```bash
# Fix log directory permissions
sudo chown -R $USER:$USER /var/log/baselfirewall
sudo chmod 755 /var/log/baselfirewall
```

### 2. Module Import Errors
```bash
# Ensure you're in virtual environment
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt
```

### 3. Iptables Issues
```bash
# Reset iptables to default
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

## Uninstallation

```bash
# Disable firewall first
sudo python3 main.py
# Select option 3 to disable firewall

# Remove configuration and logs
sudo rm -rf /var/log/baselfirewall
rm -rf config/

# Remove virtual environment
deactivate
rm -rf venv/
```

## Upgrading

```bash
# Backup configuration
cp -r config/ config_backup/

# Pull latest changes
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restore configuration if needed
cp -r config_backup/* config/
```

## Security Notes

1. Always run the firewall with sudo/root privileges
2. Keep configuration files secure (600 permissions)
3. Regularly update the system and dependencies
4. Monitor logs for suspicious activity
5. Backup configuration before upgrades

## Additional Resources

- [API Documentation](API.md)
- [Security Guidelines](SECURITY.md)
- [Troubleshooting Guide](FAQ.md)
- [Performance Tuning](PERFORMANCE.md) 