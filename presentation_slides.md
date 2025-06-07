# BaselFirewall Presentation

## Title Slide
- **Title:** BaselFirewall: A Robust Firewall Solution
- **Subtitle:** Secure, Flexible, and Easy to Use

## Overview
- **What is BaselFirewall?**
  - A Python-based firewall with advanced security features.
  - Designed for simplicity and effectiveness.

- **Key Features:**
  - Packet filtering
  - Intrusion Detection System (IDS/IPS)
  - DoS protection
  - Stateful inspection
  - User-friendly CLI and GUI

## Architecture
- **How It Works:**
  - Uses iptables for packet filtering.
  - Python modules for IDS/IPS and DoS protection.
  - Configurable via JSON files.

## Security Features
- **Packet Filtering:**
  - Default policies set to DROP.
  - Allow/block specific IPs and ports.

- **IDS/IPS:**
  - Real-time packet inspection.
  - Detects and blocks suspicious activity.

- **DoS Protection:**
  - Rate limiting for SYN and ICMP floods.
  - Prevents network overload.

## Demo
- **Enable/Disable IDS/IPS:**
  - Via CLI: `sudo python3 main.py` → Select option 1 → Enable/Disable.
  - Via GUI: `sudo python3 main.py` → Select option 2 → Use buttons.

## Testing
- **Attack Simulation:**
  - Ubuntu (attacker) vs. Kali (defender).
  - Simulate SYN floods, port scanning, etc.
  - Verify firewall blocks attacks.

## Conclusion
- **Summary:**
  - BaselFirewall is secure, flexible, and easy to use.
  - Perfect for educational and demonstration purposes.

- **Future Work:**
  - Enhance IDS/IPS capabilities.
  - Add more attack simulations.
  - Improve GUI features.

--- 