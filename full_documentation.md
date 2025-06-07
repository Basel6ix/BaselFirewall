# BaselFirewall Full Documentation

## Introduction
- **What is BaselFirewall?**
  - A Python-based firewall with advanced security features.
  - Designed for simplicity, flexibility, and effectiveness.

## Installation
- **Prerequisites:**
  - Python 3.x
  - iptables
  - tcpdump
  - Required Python packages: netifaces, psutil, cryptography

- **Installation Steps:**
  1. Clone the repository:
     ```bash
     git clone https://github.com/Basel6ix/BaselFirewall.git
     cd BaselFirewall
     ```
  2. Install required system packages:
     ```bash
     sudo apt-get install -y tcpdump python3-netifaces python3-psutil python3-cryptography
     ```
  3. Run the setup script:
     ```bash
     sudo python3 setup.py
     ```
  4. Set up the firewall service:
     ```bash
     sudo cp baselfirewall.service /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable baselfirewall.service
     sudo systemctl start baselfirewall.service
     ```
  5. Configure firewall rules:
     ```bash
     sudo chmod +x setup_firewall.sh
     sudo ./setup_firewall.sh
     ```

## Configuration
- **Configuration File:**
  - Located at `config/firewall_config.json`.
  - Contains settings for allowed/blocked IPs, ports, and feature states.

- **Key Configuration Options:**
  - `allowed_ips`: List of IPs allowed through the firewall.
  - `blocked_ips`: List of IPs blocked by the firewall.
  - `blocked_ports`: List of ports blocked by the firewall.
  - `firewall_enabled`: Toggle to enable/disable the firewall.
  - `dos_protection_enabled`: Toggle to enable/disable DoS protection.
  - `ids_ips_enabled`: Toggle to enable/disable IDS/IPS.

- **Service Configuration:**
  - The `baselfirewall.service` file configures the firewall as a system service.
  - Runs in daemon mode for continuous protection.
  - Auto-restarts on failure.
  - Logs to systemd journal.

- **Setup Script:**
  - The `setup_firewall.sh` script configures initial firewall rules:
    - Sets default policies to DROP
    - Configures essential service rules (SSH, DNS, HTTP/HTTPS)
    - Sets up rate limiting
    - Configures logging
    - Creates necessary directories and files

## Usage
- **Command Line Interface (CLI):**
  - Launch the CLI:
    ```bash
    sudo python3 main.py
    ```
  - Select option `1` to launch the CLI.
  - Use the menu to enable/disable features, view status, etc.

- **Graphical User Interface (GUI):**
  - Launch the GUI:
    ```bash
    sudo python3 main.py
    ```
  - Select option `2` to launch the GUI.
  - Use buttons or toggles to control the firewall.

- **Service Management:**
  - Check service status:
    ```bash
    sudo systemctl status baselfirewall.service
    ```
  - View logs:
    ```bash
    sudo journalctl -u baselfirewall.service
    ```
  - Restart service:
    ```bash
    sudo systemctl restart baselfirewall.service
    ```

## Security Features
- **Packet Filtering:**
  - Default policies set to DROP.
  - Allow/block specific IPs and ports.

- **Intrusion Detection System (IDS/IPS):**
  - Real-time packet inspection.
  - Detects and blocks suspicious activity.
  - Enable/disable via CLI or GUI.

- **DoS Protection:**
  - Rate limiting for SYN and ICMP floods.
  - Prevents network overload.

- **Stateful Inspection:**
  - Tracks connection states.
  - Allows related traffic.
  - Blocks invalid packets.

## Testing
- **Attack Simulation:**
  - **Setup:**
    - Ubuntu (attacker) and Kali (defender) on the same network.
  - **Attack Scenarios:**
    - SYN flood attack:
      ```bash
      sudo hping3 -S -p 80 -c 1000 192.168.1.100
      ```
    - Port scanning:
      ```bash
      sudo nmap -sS 192.168.1.100
      ```
  - **Defense Verification:**
    - Check firewall logs:
      ```bash
      sudo tail -f /var/log/baselfirewall/firewall.log
      ```
    - Verify attacks are blocked.

## Troubleshooting
- **Common Issues:**
  - IDS/IPS not running: Ensure tcpdump is installed and run the enable command.
  - Firewall rules not applied: Check iptables rules with `sudo iptables -L -n -v`.
  - Logging issues: Ensure log directory exists and has correct permissions.
  - Service not starting: Check systemd logs with `journalctl -u baselfirewall.service`.

## Future Work
- Enhance IDS/IPS capabilities.
- Add more attack simulations.
- Improve GUI features.
- Implement log rotation and advanced analytics.

--- 