# Attack Testing Guide for BaselFirewall

## Setup
- **Attacker (Ubuntu):**
  - Install required tools:
    ```bash
    sudo apt-get install -y hping3 nmap
    ```
  - Ensure Ubuntu and Kali are on the same network.

- **Defender (Kali):**
  - Ensure BaselFirewall service is running:
    ```bash
    sudo systemctl status baselfirewall.service
    ```
  - If not running, start the service:
    ```bash
    sudo systemctl start baselfirewall.service
    ```
  - Enable IDS/IPS:
    ```bash
    sudo python3 -c "from firewall.ids_ips import enable_ids_ips; enable_ids_ips()"
    ```

## Attack Scenarios
- **1. SYN Flood Attack:**
  - On Ubuntu (attacker), run:
    ```bash
    sudo hping3 -S -p 80 -c 1000 192.168.1.100
    ```
  - This sends 1000 SYN packets to port 80 on the Kali machine.

- **2. Port Scanning:**
  - On Ubuntu (attacker), run:
    ```bash
    sudo nmap -sS 192.168.1.100
    ```
  - This scans for open ports on the Kali machine.

## Defense Verification
- **Check Service Status:**
  - On Kali (defender), run:
    ```bash
    sudo systemctl status baselfirewall.service
    ```
  - Ensure service is active and running.

- **Check Firewall Logs:**
  - On Kali (defender), run:
    ```bash
    sudo tail -f /var/log/baselfirewall/firewall.log
    ```
  - Verify that attacks are logged and blocked.

- **Check iptables Rules:**
  - On Kali (defender), run:
    ```bash
    sudo iptables -L -n -v
    ```
  - Ensure rules are active and blocking attacks.

## Expected Results
- **SYN Flood Attack:**
  - Firewall should log the attack and block excessive SYN packets.
  - No service disruption on Kali.
  - Service should remain active during attack.

- **Port Scanning:**
  - Firewall should log the scan and block unauthorized access.
  - Only allowed ports should be accessible.
  - Service should remain stable during scan.

## Conclusion
- BaselFirewall effectively blocks common attacks.
- Logs provide clear evidence of attempted attacks.
- Service remains stable under attack conditions.
- Perfect for educational and demonstration purposes.

--- 