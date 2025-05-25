# BaselFirewall - Personal Firewall Project

© 2025 B. Abu-Radaha. All Rights Reserved.

A comprehensive network security solution with advanced firewall capabilities, intrusion detection/prevention, and user-friendly management interface.

## Overview
**BaselFirewall** is a Python-based personal firewall developed for Linux systems. It provides comprehensive network protection using rule-based filtering, intrusion detection, stateful inspection, and advanced security features. The project includes both a command-line interface (CLI) and a graphical interface (GUI) for flexible management.

## Key Features
- **Advanced Packet Filtering**
  - IP-based allow/block lists
  - Port-based filtering
  - Protocol-specific rules
  - Rule prioritization
  - Stateful connection tracking

- **Intrusion Detection & Prevention (IDS/IPS)**
  - Real-time packet inspection
  - SYN flood detection
  - DoS/DDoS protection
  - Brute force attack prevention
  - Configurable detection thresholds

- **Authentication & Access Control**
  - Role-based access (admin/user)
  - Secure password hashing (bcrypt)
  - Rate limiting for login attempts
  - Session management
  - Password policy enforcement

- **Monitoring & Logging**
  - Detailed event logging
  - Real-time alerts
  - Traffic analysis
  - System statistics
  - Audit trail for admin actions

- **User Interface**
  - Feature-rich CLI
  - Modern GUI with Tkinter
  - Real-time monitoring
  - Rule management interface
  - System status dashboard

## System Requirements
- Linux-based operating system
- Python 3.8 or higher
- Root/sudo privileges for firewall operations
- Required system packages:
  ```bash
  sudo apt-get update
  sudo apt-get install python3-tk tcpdump
  ```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/BaselFirewall.git
   cd BaselFirewall
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the firewall:
   ```bash
   sudo python setup.py install
   ```

## Usage

### Command Line Interface
```bash
# Start the CLI
sudo python main.py

# Direct commands
sudo python main.py --allow-ip 192.168.1.100
sudo python main.py --block-port 8080
sudo python main.py --enable-ids
```

### Graphical Interface
```bash
# Start the GUI
sudo python gui/interface.py
```

### Common Operations
1. **Managing Rules**
   ```bash
   # Allow an IP
   sudo python main.py --allow-ip IP_ADDRESS

   # Block a port
   sudo python main.py --block-port PORT_NUMBER

   # Remove a rule
   sudo python main.py --remove-rule RULE_ID
   ```

2. **User Management**
   ```bash
   # Add a user
   sudo python main.py --add-user USERNAME

   # Change password
   sudo python main.py --change-password USERNAME

   # List users (admin only)
   sudo python main.py --list-users
   ```

3. **System Control**
   ```bash
   # Enable features
   sudo python main.py --enable-feature FEATURE_NAME

   # View logs
   sudo python main.py --view-logs

   # Check status
   sudo python main.py --status
   ```

## Security Features

### Rate Limiting
- Maximum 5 failed login attempts within 5 minutes
- IP-based blocking for excessive attempts
- Automatic IDS notification for potential brute force

### IDS/IPS Capabilities
- SYN flood detection
- Connection rate monitoring
- Pattern-based attack detection
- Automatic threat response
- Configurable alert thresholds

### Logging and Monitoring
- Detailed event logging
- IP-based activity tracking
- Rule match logging
- System performance metrics
- Security event alerts

## Project Structure
```
BaselFirewall/
├── main.py                 # Main entry point
├── cli/                    # CLI implementation
├── gui/                    # GUI implementation
├── firewall/              # Core firewall modules
│   ├── rules.py           # Rule management
│   ├── ids_ips.py         # IDS/IPS implementation
│   ├── auth.py            # Authentication
│   └── logging.py         # Logging system
├── config/                # Configuration files
├── logs/                  # Log files
├── tests/                 # Test suite
└── resources/             # Additional resources
```

## Development

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=firewall tests/
```

### Code Style
```bash
# Format code
black .

# Check style
flake8
```

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
This project is developed for academic purposes and is available for educational use under the MIT License.

## Credits
Developed by **B. Abu-Radaha**  
Supervised by **M. Nabarawi**  
Graduation Project – **Hittien College**, May 2025

## Acknowledgments
- Grateful to Al-Hareth for providing the hardware support and testing infrastructure
- Special thanks to the Cybersecurity Lab at Hittien College
- Thanks to all beta testers and contributors

## Support
For issues and questions, please open an issue on the GitHub repository.
