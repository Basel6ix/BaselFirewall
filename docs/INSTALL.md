# Installation Guide

This guide provides detailed instructions for installing and configuring BaselFirewall on your Linux system.

## Prerequisites

### System Requirements
- Linux distribution (Ubuntu 20.04+ or similar)
- Python 3.8 or higher
- Root/sudo privileges
- 2GB RAM minimum
- 500MB free disk space

### Required System Packages
```bash
# Update package list
sudo apt-get update

# Install required system packages
sudo apt-get install -y \
    python3-dev \
    python3-pip \
    python3-venv \
    python3-tk \
    iptables \
    tcpdump \
    net-tools
```

## Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/BaselFirewall.git
   cd BaselFirewall
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python Dependencies**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Configure Firewall**
   ```bash
   # Create necessary directories
   sudo mkdir -p /var/log/baselfirewall
   sudo chmod 755 /var/log/baselfirewall

   # Initialize configuration
   sudo python setup.py install
   ```

## Post-Installation Setup

1. **Create Admin User**
   ```bash
   sudo python register_user.py
   ```
   Follow the prompts to create an admin account.

2. **Verify Installation**
   ```bash
   sudo python main.py --status
   ```
   You should see "BaselFirewall is running" if everything is configured correctly.

3. **Configure Autostart (Optional)**
   To start BaselFirewall automatically at boot:
   ```bash
   sudo cp resources/baselfirewall.service /etc/systemd/system/
   sudo systemctl enable baselfirewall
   sudo systemctl start baselfirewall
   ```

## Common Issues and Solutions

### Permission Errors
If you encounter permission errors:
```bash
sudo chown -R $USER:$USER /var/log/baselfirewall
sudo chmod 755 /var/log/baselfirewall
```

### Python Version Conflicts
If you have multiple Python versions:
```bash
# Verify Python version
python3 --version

# If needed, install specific version
sudo apt-get install python3.8
```

### Dependency Issues
If you encounter dependency conflicts:
```bash
pip install --upgrade -r requirements.txt --no-cache-dir
```

## Uninstallation

To completely remove BaselFirewall:
```bash
# Stop the service
sudo systemctl stop baselfirewall
sudo systemctl disable baselfirewall

# Remove files
sudo rm -rf /var/log/baselfirewall
sudo rm /etc/systemd/system/baselfirewall.service

# Remove Python package
pip uninstall baselfirewall -y
```

## Next Steps

- Read the [User Guide](user/installation.md) for usage instructions
- Configure [Security Features](user/security_features.md)
- Review [FAQ](FAQ.md) for common questions
- Check [Troubleshooting Guide](TROUBLESHOOTING.md) for detailed problem-solving

## Support

If you encounter any issues during installation:
1. Check the [FAQ](FAQ.md)
2. Search existing [GitHub Issues](https://github.com/yourusername/BaselFirewall/issues)
3. Create a new issue with detailed information about your problem 