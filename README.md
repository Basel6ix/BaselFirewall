# BaselFirewall

A powerful, Python-based firewall with advanced security features including IDS/IPS capabilities, DoS protection, and real-time monitoring.

![BaselFirewall Logo](docs/images/logo.png)

## Features

- 🔒 **Advanced Security**
  - Packet filtering and stateful inspection
  - Intrusion Detection and Prevention System (IDS/IPS)
  - Denial of Service (DoS) protection
  - Real-time attack detection and prevention

- 🛠️ **Easy Management**
  - User-friendly CLI and GUI interfaces
  - Simple JSON configuration
  - Comprehensive logging system
  - Real-time monitoring and alerts

- 🚀 **Performance**
  - Efficient packet processing
  - Low resource usage
  - Scalable architecture
  - Optimized rule management

## Installation

### Prerequisites

- Python 3.x
- Linux operating system
- iptables
- tcpdump
- Required Python packages

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/BaselFirewall.git
   cd BaselFirewall
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the setup script:
   ```bash
   sudo python3 setup.py install
   ```

4. Start the firewall:
   ```bash
   sudo python3 main.py
   ```

## Usage

### Basic Commands

```bash
# Start the firewall
sudo python3 main.py

# Enable IDS/IPS
sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"

# Check status
sudo systemctl status baselfirewall.service

# View logs
sudo tail -f /var/log/baselfirewall/firewall.log
```

### Configuration

The firewall is configured using JSON files in the `config` directory. See [Configuration Guide](docs/configuration/options_guide.md) for details.

Example configuration:
```json
{
    "firewall": {
        "enabled": true,
        "default_policy": "DROP",
        "interfaces": ["eth0"]
    }
}
```

## Documentation

- [User Guide](docs/user/complete_guide.md)
- [Configuration Guide](docs/configuration/options_guide.md)
- [Security Features](docs/security/best_practices.md)
- [Troubleshooting](docs/troubleshooting/guide.md)
- [API Reference](docs/technical/api_reference.md)

## Security Features

### IDS/IPS
- Real-time packet inspection
- Attack pattern detection
- Automatic blocking of malicious traffic
- Customizable rules and thresholds

### DoS Protection
- Rate limiting
- Connection tracking
- SYN flood protection
- Resource usage monitoring

### Logging
- Comprehensive event logging
- Real-time alerts
- Log rotation
- Analysis tools

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Testing

Run the test suite:
```bash
python3 -m pytest tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors
- Inspired by various open-source security projects
- Built with Python and Linux security tools

## Contact

- GitHub Issues: [Report bugs or request features](https://github.com/yourusername/BaselFirewall/issues)
- Email: [Your Email]
- Documentation: [Full Documentation](docs/)

## Roadmap

- [ ] Machine learning for attack detection
- [ ] Cloud integration
- [ ] Mobile management interface
- [ ] Advanced reporting system
- [ ] Additional attack signatures

---

Made with ❤️ by [Your Name]
