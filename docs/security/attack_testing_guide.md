# BaselFirewall Attack Testing Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

# Attack Testing Guide: Ubuntu (Attacker) vs Kali (Defender)

## Test Environment Setup

### 1. Network Configuration
```ascii
+----------------+     +----------------+
|    Ubuntu      |     |     Kali       |
|   (Attacker)   |<--->|   (Defender)   |
|  192.168.1.10  |     |  192.168.1.20  |
+----------------+     +----------------+
```

### 2. System Requirements

#### Ubuntu (Attacker)
```bash
# Install required tools
sudo apt-get update
sudo apt-get install -y nmap hping3 netcat python3-scapy

# Verify installations
nmap --version
hping3 --version
python3 -c "import scapy; print(scapy.__version__)"
```

#### Kali (Defender)
```bash
# Verify BaselFirewall installation
sudo systemctl status baselfirewall.service

# Check IDS/IPS status
sudo python3 -c "from firewall.ids_ips import check_status; check_status()"

# Verify logging
sudo tail -f /var/log/baselfirewall/firewall.log
```

## Attack Scenarios

### 1. Port Scanning Attack
```bash
# On Ubuntu (Attacker)
# Basic port scan
nmap -sS 192.168.1.20

# Aggressive scan
nmap -A -T4 192.168.1.20

# Full port scan
nmap -p- 192.168.1.20
```

#### Expected Results
- BaselFirewall should detect and log the scan
- IDS/IPS should trigger alerts
- Firewall should block repeated scan attempts

### 2. SYN Flood Attack
```bash
# On Ubuntu (Attacker)
# Basic SYN flood
sudo hping3 -S -p 80 -c 1000 192.168.1.20

# Continuous SYN flood
sudo hping3 -S -p 80 --flood 192.168.1.20
```

#### Expected Results
- DoS protection should activate
- Rate limiting should block excessive packets
- Logs should show attack detection

### 3. Brute Force Attempt
```bash
# On Ubuntu (Attacker)
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.20

# FTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.20
```

#### Expected Results
- IDS/IPS should detect multiple failed attempts
- Firewall should block the attacking IP
- Logs should show brute force detection

## Defense Verification

### 1. On Kali (Defender)
```bash
# Monitor firewall logs
sudo tail -f /var/log/baselfirewall/firewall.log

# Check IDS/IPS alerts
sudo python3 -c "from firewall.ids_ips import show_alerts; show_alerts()"

# View blocked IPs
sudo python3 -c "from firewall.rules import show_blocked_ips; show_blocked_ips()"
```

### 2. Defense Metrics
- Attack detection time
- Blocking effectiveness
- Resource usage during attacks
- False positive rate

## Attack Testing Procedure

### 1. Preparation
```bash
# On Kali (Defender)
# Enable all security features
sudo python3 -c "from firewall.core import enable_all_features; enable_all_features()"

# Verify configuration
sudo python3 -c "from firewall.config import validate_security; validate_security()"
```

### 2. Execution
```bash
# On Ubuntu (Attacker)
# Run attack sequence
./attack_sequence.sh

# On Kali (Defender)
# Monitor defense
./monitor_defense.sh
```

### 3. Analysis
```bash
# On Kali (Defender)
# Generate attack report
sudo python3 -c "from firewall.reports import generate_attack_report; generate_attack_report()"

# Analyze logs
sudo python3 -c "from firewall.analysis import analyze_attack_logs; analyze_attack_logs()"
```

## Expected Results

### 1. Port Scanning
- Detection within 5 seconds
- Blocking of scanning IP
- Logging of scan attempts
- Alert generation

### 2. SYN Flood
- Rate limiting activation
- Connection tracking
- Resource protection
- Attack source blocking

### 3. Brute Force
- Multiple attempt detection
- IP blocking after threshold
- Alert generation
- Logging of attempts

## Security Recommendations

### 1. For Ubuntu (Attacker)
- Use in controlled environment
- Document all test cases
- Follow ethical guidelines
- Report vulnerabilities

### 2. For Kali (Defender)
- Regular security updates
- Monitor system resources
- Review logs daily
- Update attack signatures

## Troubleshooting

### 1. Common Issues
- False positives
- Performance impact
- Detection delays
- Blocking effectiveness

### 2. Solutions
- Adjust thresholds
- Optimize rules
- Update signatures
- Fine-tune configuration

## Best Practices

### 1. Testing
- Start with basic attacks
- Gradually increase complexity
- Document all results
- Verify defense effectiveness

### 2. Security
- Regular updates
- Log analysis
- Performance monitoring
- Rule optimization

## Conclusion

This guide provides a framework for testing BaselFirewall's security features using Ubuntu as the attacker and Kali as the defender. Always perform these tests in a controlled environment and follow ethical guidelines.

--- 