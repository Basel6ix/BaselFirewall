# BaselFirewall

A comprehensive, Python-based personal firewall for Linux systems with advanced security features and user-friendly interfaces.

## Author Information

- **Author:** Basel Abu-Radaha (B. Abu-Radaha)
- **Supervisor:** Mohammad Nabrawi (M. Nabrawi)
- **Institution:** Hittien College
- **Project Type:** Graduation Project (2025)
- **Contact:** baselyt24@gmail.com
- **License:** MIT

## Features

- **Advanced Packet Filtering**: Fine-grained control over network traffic
- **Intrusion Detection/Prevention (IDS/IPS)**: Real-time threat detection and prevention
- **DoS Protection**: Defense against Denial of Service attacks
- **Network Address Translation (NAT)**: Support for network address translation
- **Stateful Inspection**: Intelligent packet filtering based on connection state
- **User Authentication**: Secure multi-user access with role-based permissions
- **Dual Interface**: Both CLI and GUI for flexible management
- **Comprehensive Logging**: Detailed activity tracking and alert system

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/BaselFirewall.git
   cd BaselFirewall
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the firewall:
   ```bash
   sudo python main.py
   ```

## Documentation

- [Installation Guide](docs/INSTALL.md)
- [User Guide](docs/user/installation.md)
- [Security Features](docs/user/security_features.md)
- [API Reference](docs/technical/api_reference.md)
- [Contributing Guidelines](docs/CONTRIBUTING.md)
- [FAQ](docs/FAQ.md)

## Project Structure

```
BaselFirewall/
├── cli/                 # Command-line interface
├── config/             # Configuration files
├── docs/               # Documentation
├── firewall/           # Core firewall functionality
├── gui/                # Graphical user interface
├── logs/               # Log files
├── resources/          # Project resources
└── tests/              # Test suite
```

## Security Features

- Rate limiting for connection attempts
- SYN flood protection
- ICMP flood protection
- IP blacklisting
- Port blocking
- Stateful packet inspection
- Real-time threat detection
- Comprehensive logging and alerts

## Requirements

- Python 3.8+
- Linux system with iptables
- Root privileges for firewall operations
- Additional requirements in requirements.txt

## Contributing

Please read our [Contributing Guidelines](docs/CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- [Report Issues](https://github.com/yourusername/BaselFirewall/issues)
- [FAQ](docs/FAQ.md)
- [Security Policy](docs/SECURITY.md)
