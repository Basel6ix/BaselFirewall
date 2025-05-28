# BaselFirewall FAQ

## General Questions

### Q: What is BaselFirewall?
A: BaselFirewall is a Python-based personal firewall for Linux systems that provides advanced packet filtering, intrusion detection/prevention, and user management capabilities.

### Q: What operating systems are supported?
A: BaselFirewall is designed for Linux systems, specifically tested on:
- Ubuntu 20.04+
- Debian 10+
- Kali Linux 2021+

### Q: Do I need root access?
A: Yes, root/sudo access is required as the firewall needs to modify iptables rules and system configurations.

## Installation

### Q: How do I install BaselFirewall?
A: Follow these steps:
1. Clone the repository
2. Create a virtual environment
3. Install dependencies
4. Run the setup script
Detailed instructions are in [INSTALL.md](INSTALL.md).

### Q: Why am I getting permission errors?
A: Common causes:
1. Not running with sudo
2. Incorrect file permissions
3. SELinux/AppArmor restrictions

Solution: Check [INSTALL.md](INSTALL.md) troubleshooting section.

### Q: Can I install without virtual environment?
A: Not recommended. The virtual environment ensures dependency isolation and prevents conflicts.

## Configuration

### Q: How do I configure network interfaces?
A: Edit `config/firewall_config.json`:
```json
{
    "nat_config": {
        "external_interface": "eth0",
        "internal_interface": "eth1",
        "internal_network": "192.168.1.0/24"
    }
}
```

### Q: How do I add allowed IPs?
A: Three methods:
1. CLI: `sudo python3 main.py` → Option 1 → Add IP
2. GUI: Launch GUI → Firewall Rules tab → Add IP
3. Direct: Edit `config/firewall_config.json`

### Q: How do I reset to default settings?
A: Use the reset function:
1. CLI: Select "Reset Configuration"
2. GUI: Configuration tab → Reset
3. Manual: Delete `config/*.json` and restart

## Usage

### Q: How do I start the firewall?
A: Run `sudo python3 main.py` and choose:
1. CLI interface
2. GUI interface

### Q: How do I check if it's running?
A: Several methods:
1. Check main menu status
2. Run `sudo iptables -L`
3. Check logs in `/var/log/baselfirewall/`

### Q: How do I disable the firewall in emergency?
A: Two methods:
1. Main menu: Option 3 (Toggle Firewall)
2. Direct command: `sudo python3 main.py -d`

## Features

### Q: What protection features are available?
A: Main features:
- Packet filtering
- DoS protection
- IDS/IPS
- NAT
- Stateful inspection
- User authentication

### Q: How does DoS protection work?
A: BaselFirewall implements:
1. SYN flood protection
2. ICMP flood protection
3. Connection rate limiting
4. IP blacklisting

### Q: Can I customize protection rules?
A: Yes, through:
1. Configuration files
2. CLI interface
3. GUI interface

## Troubleshooting

### Q: Firewall blocks legitimate traffic?
Steps to resolve:
1. Check logs: `/var/log/baselfirewall/firewall.log`
2. Verify rules: `sudo iptables -L`
3. Add IP to allowed list if needed
4. Check [SECURITY.md](SECURITY.md) for guidance

### Q: GUI won't start?
Common causes:
1. Missing dependencies
2. Permission issues
3. Display server problems

Solution:
```bash
# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt

# Check permissions
sudo chown -R $USER:$USER ~/.cache/baselfirewall
```

### Q: Logs show many blocked connections?
This could indicate:
1. DoS attack attempt
2. Misconfigured allowed IPs
3. Application trying to connect

Check [SECURITY.md](SECURITY.md) for analysis steps.

## Performance

### Q: Will BaselFirewall slow down my system?
A: Impact is minimal:
- CPU usage < 5%
- Memory usage < 100MB
- Network latency +1-2ms

### Q: How many rules can I add?
A: Practical limits:
- Allowed IPs: 10,000
- Blocked IPs: 100,000
- Custom rules: 5,000

### Q: How to optimize performance?
Tips:
1. Regular log rotation
2. Clean old rules
3. Use efficient IP ranges
4. Enable caching

## Development

### Q: How can I contribute?
A: See [CONTRIBUTING.md](CONTRIBUTING.md) for:
1. Code style guide
2. Pull request process
3. Testing requirements

### Q: How do I report bugs?
A: For bugs:
1. Check existing issues
2. Create detailed report
3. Include logs and steps
4. Follow template

### Q: Where are the logs?
A: Log locations:
- `/var/log/baselfirewall/firewall.log`
- `/var/log/baselfirewall/auth.log`
- `/var/log/baselfirewall/error.log`

## Updates and Maintenance

### Q: How often should I update?
Recommended schedule:
- Daily: Check logs
- Weekly: Update rules
- Monthly: Full update
- Quarterly: Security audit

### Q: How do I backup settings?
A: Backup process:
```bash
# Backup all configs
cp -r config/ config_backup/

# Backup specific files
cp config/firewall_config.json backup/
cp config/users.json backup/
```

### Q: How do I restore from backup?
A: Restore process:
```bash
# Stop firewall
sudo python3 main.py -d

# Restore configs
cp -r config_backup/* config/

# Restart firewall
sudo python3 main.py
``` 