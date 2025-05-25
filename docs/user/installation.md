# Installation Guide

## System Requirements
- Python 3.8 or higher
- Linux operating system (Ubuntu 20.04+ or similar)
- Root/sudo access
- 2GB RAM minimum
- 1GB free disk space

## Prerequisites
1. Update system packages:
```bash
sudo apt update
sudo apt upgrade -y
```

2. Install Python dependencies:
```bash
sudo apt install -y python3-pip python3-dev build-essential libnetfilter-queue-dev
```

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/Basel6ix/BaselFirewall.git
cd BaselFirewall
```

### 2. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 3. Install BaselFirewall
```bash
sudo python3 setup.py install
```

### 4. Configure Service
```bash
sudo cp resources/baselfirewall.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 5. Start Service
```bash
sudo systemctl start baselfirewall
sudo systemctl enable baselfirewall
```

### 6. Verify Installation
```bash
sudo systemctl status baselfirewall
```

## Initial Configuration

### 1. Create Admin User
```bash
sudo python3 register_user.py --admin
```

### 2. Configure Firewall Rules
```bash
sudo python3 -m baselfirewall.gui
```

## Troubleshooting

### Common Issues

1. Service Won't Start
```bash
# Check logs
sudo journalctl -u baselfirewall -n 50
```

2. Permission Issues
```bash
# Fix permissions
sudo chown -R root:root /etc/baselfirewall
sudo chmod 755 /etc/baselfirewall
```

3. Port Conflicts
```bash
# Check port usage
sudo netstat -tulpn | grep LISTEN
```

### Getting Help
- Check GitHub Issues
- Join our community forum
- Contact support

## Uninstallation
```bash
# Stop service
sudo systemctl stop baselfirewall
sudo systemctl disable baselfirewall

# Remove files
sudo rm /etc/systemd/system/baselfirewall.service
sudo rm -rf /etc/baselfirewall

# Remove Python package
sudo pip3 uninstall baselfirewall
```

## Next Steps
- [GUI Guide](gui_guide.md)
- [Security Features](security_features.md)
- [User Management](user_management.md) 