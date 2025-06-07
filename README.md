# BaselFirewall

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Overview
BaselFirewall is an advanced network security solution that combines traditional firewall capabilities with modern intrusion detection and prevention features. Built in Python, it provides a robust, flexible, and user-friendly interface for managing network security.

## Key Features
- 🔒 **Advanced Firewall**
  - Stateful packet inspection
  - NAT support
  - Port forwarding
  - IP and port filtering
  - Connection tracking

- 🛡️ **IDS/IPS**
  - Real-time packet inspection
  - Attack pattern detection
  - Automatic threat response
  - Custom rule creation

- 🚫 **DoS Protection**
  - Rate limiting
  - SYN flood protection
  - Connection limiting
  - Traffic shaping

- 📊 **Monitoring & Logging**
  - Real-time traffic monitoring
  - Detailed logging system
  - Log rotation
  - Alert notifications

- 🖥️ **User Interface**
  - Command-line interface (CLI)
  - Graphical user interface (GUI)
  - Web-based dashboard
  - Configuration management

## Quick Start

### Prerequisites
- Python 3.x
- iptables
- tcpdump
- root/sudo access

### Installation
```bash
# Clone the repository
git clone https://github.com/Basel6ix/BaselFirewall.git
cd BaselFirewall

# Install dependencies
sudo pip3 install -r requirements.txt

# Run setup script
sudo ./setup_firewall.sh

# Start the service
sudo systemctl start baselfirewall.service
```

### Basic Usage
```bash
# Start the firewall
sudo python3 main.py

# Enable IDS/IPS
sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"

# View logs
sudo tail -f /var/log/baselfirewall/firewall.log
```

## Documentation
- [User Guide](docs/user/complete_guide.md)
- [Installation Guide](docs/INSTALL.md)
- [Security Guide](docs/SECURITY.md)
- [API Reference](docs/API.md)
- [Troubleshooting](docs/troubleshooting/guide.md)
- [Attack Testing](docs/security/attack_testing_guide.md)

## Security Features
- Default DROP policies
- Rate limiting for ICMP and SSH
- Port scanning detection
- SYN flood protection
- IP blacklisting
- Connection tracking
- Secure configuration management

## Contributing
Please read our [Contributing Guide](docs/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Supervisor: M. Nabrawi
- Hittien College
- All contributors and testers

## Contact
For support or questions, please open an issue in the GitHub repository or contact the development team.

## Version
Current version: 1.0.0
