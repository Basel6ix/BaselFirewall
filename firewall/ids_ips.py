import time
import subprocess
import re
import socket
import netifaces
import os
import logging
from collections import defaultdict
from threading import Thread, Event, Lock
from scapy.all import IP, TCP, UDP, ICMP
from firewall.config_manager import (
    add_blocked_ip,
    load_config,
    save_config,
    set_feature_state,
    get_feature_state,
)
from firewall.alerts import add_alert
from firewall.logging import log_event


class PacketInspector:
    def __init__(self):
        self.suspicious_ips = defaultdict(
            lambda: {
                "count": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "states": defaultdict(int),
                "ssh_attempts": {
                    "count": 0,
                    "last_attempt": 0,
                    "blocked_until": 0,
                    "failed_usernames": set(),
                },
            }
        )
        self.lock = Lock()
        self.config = self._load_ids_config()

    def _load_ids_config(self):
        config = load_config()
        if "ids_config" not in config:
            config["ids_config"] = {
                "dos_threshold": 50,
                "dos_window": 10,
                "syn_flood_threshold": 30,
                "syn_flood_window": 5,
                "failed_auth_threshold": 5,
                "failed_auth_window": 60,
                "ssh_attempt_threshold": 5,
                "ssh_block_duration": 3600,  # 1 hour
                "ssh_detection_window": 300,  # 5 minutes
                "ssh_alert_threshold": 3,  # Alert after 3 failed attempts
                "port_scan_threshold": 15,  # Number of different ports
                "port_scan_window": 60,  # Time window in seconds
                "syn_scan_rate": 100,  # SYNs per second for nmap detection
                "syn_scan_ports": 10,  # Different ports in short time
                "syn_scan_window": 5,  # Window for SYN scan detection (seconds)
            }
            save_config(config)
        return config["ids_config"]

    def inspect_packet(self, packet, ip):
        with self.lock:
            now = time.time()
            data = self.suspicious_ips[ip]

            # Reset counters if window expired
            if now - data["first_seen"] > self.config["dos_window"]:
                data["count"] = 0
                data["first_seen"] = now
                data["syn_count"] = 0
                data["alerted"] = False

            # Update packet count
            data["count"] += 1

            # First check for port scan/SYN scan
            if self.detect_port_scan(packet, ip):
                return True

            # Check for SYN flood
            if "SYN" in packet:
                if now - data["last_syn"] > self.config["syn_flood_window"]:
                    data["syn_count"] = 0
                data["syn_count"] += 1
                data["last_syn"] = now

                if data["syn_count"] > self.config["syn_flood_threshold"]:
                    message = f"ALERT: SYN flood attack detected from {ip}"
                    self._handle_threat(ip, message, "syn_flood")
                    return True

            # Check for DoS
            if data["count"] > self.config["dos_threshold"]:
                message = f"ALERT: Possible DoS attack from {ip}"
                self._handle_threat(ip, message, "dos")
                return True

            return False

    def detect_port_scan(self, packet, ip):
        """
        Enhanced port scan detection specifically for nmap SYN scans
        """
        now = time.time()
        data = self.suspicious_ips[ip]

        # Initialize port scan tracking if needed
        if "port_scan" not in data:
            data["port_scan"] = {
                "ports": set(),
                "last_scan": 0,
                "count": 0,
                "syn_count": 0,
                "syn_start": now,
            }

        scan_data = data["port_scan"]

        # Check if this is a SYN packet
        if "SYN" in packet and "ACK" not in packet:
            port_match = re.search(r"dport (\d+)", packet.lower())
            if port_match:
                port = int(port_match.group(1))

                # Track unique ports
                scan_data["ports"].add(port)
                scan_data["syn_count"] += 1

                # Reset counters if window expired
                if now - scan_data["syn_start"] > self.config["syn_scan_window"]:
                    scan_data["syn_count"] = 1
                    scan_data["syn_start"] = now
                    scan_data["ports"] = {port}

                # Check for nmap SYN scan pattern
                syn_rate = scan_data["syn_count"] / self.config["syn_scan_window"]
                if (
                    syn_rate >= self.config["syn_scan_rate"]
                    and len(scan_data["ports"]) >= self.config["syn_scan_ports"]
                ):
                    message = (
                        f"ALERT: Nmap SYN scan detected from {ip} "
                        f"(Rate: {syn_rate:.1f} SYN/s, Ports: {len(scan_data['ports'])})"
                    )
                    log_event(message, "WARNING")
                    add_alert(message, "WARNING")
                    self._handle_threat(ip, message, "port_scan")
                    return True

                # Check for general port scan pattern
                if now - scan_data["last_scan"] > self.config["port_scan_window"]:
                    scan_data["count"] = 1
                else:
                    scan_data["count"] += 1

                scan_data["last_scan"] = now

                if scan_data["count"] >= self.config["port_scan_threshold"]:
                    message = (
                        f"ALERT: Port scan detected from {ip} "
                        f"({scan_data['count']} ports in {self.config['port_scan_window']}s)"
                    )
                    log_event(message, "WARNING")
                    add_alert(message, "WARNING")
                    self._handle_threat(ip, message, "port_scan")
                    return True

        return False

    def record_failed_auth(self, ip):
        with self.lock:
            now = time.time()
            data = self.suspicious_ips[ip]

            if (
                now - data.get("last_failed_auth", 0)
                > self.config["failed_auth_window"]
            ):
                data["failed_auth"] = 0

            data["failed_auth"] += 1
            data["last_failed_auth"] = now

            if (
                data["failed_auth"] >= self.config["failed_auth_threshold"]
                and not data["alerted"]
            ):
                data["alerted"] = True
                message = f"ALERT: Multiple failed authentication attempts from {ip}"
                self._handle_threat(ip, message, "failed_auth")
                return message

            return None

    def detect_ssh_brute_force(self, src_ip, username=None, success=False):
        """
        Enhanced SSH brute force detection with username tracking and adaptive blocking
        """
        now = time.time()
        data = self.suspicious_ips[src_ip]["ssh_attempts"]

        # Check if IP is currently blocked
        if data["blocked_until"] > now:
            remaining = int(data["blocked_until"] - now)
            log_event(
                f"Blocked SSH attempt from {src_ip} (blocked for {remaining}s more)",
                "WARNING",
            )
            return True

        # Reset counter if detection window has passed
        if now - data["last_attempt"] > self.config["ssh_detection_window"]:
            data["count"] = 0
            data["failed_usernames"] = set()

        # Track the attempt
        if not success:
            data["count"] += 1
            if username:
                data["failed_usernames"].add(username)
            data["last_attempt"] = now

            # Alert on suspicious activity
            if data["count"] >= self.config["ssh_alert_threshold"]:
                message = (
                    f"SSH brute force attempt detected from {src_ip} "
                    f"({data['count']} failed attempts, "
                    f"usernames: {', '.join(data['failed_usernames'])})"
                )
                log_event(message, "WARNING")

            # Block if threshold exceeded
            if data["count"] >= self.config["ssh_attempt_threshold"]:
                data["blocked_until"] = now + self.config["ssh_block_duration"]
                message = (
                    f"Blocking SSH from {src_ip} for {self.config['ssh_block_duration']}s "
                    f"due to brute force attempt"
                )
                log_event(message, "WARNING")

                # Add IPTables rules
                try:
                    # Drop all SSH traffic from this IP
                    subprocess.run(
                        [
                            "iptables",
                            "-A",
                            "INPUT",
                            "-p",
                            "tcp",
                            "--dport",
                            "22",
                            "-s",
                            src_ip,
                            "-j",
                            "DROP",
                        ],
                        check=True,
                    )

                    # Add rule to remove the block after duration
                    unblock_cmd = (
                        f"iptables -D INPUT -p tcp --dport 22 -s {src_ip} -j DROP"
                    )
                    subprocess.run(
                        [
                            "at",
                            "now",
                            "+",
                            str(self.config["ssh_block_duration"]),
                            "seconds",
                        ],
                        input=unblock_cmd.encode(),
                        check=True,
                    )

                    return True
                except subprocess.CalledProcessError as e:
                    log_event(
                        f"Failed to add IPTables rule for SSH blocking: {e}", "ERROR"
                    )

        return False

    def _handle_threat(self, ip, message, attack_type):
        print(message)
        add_alert(message, "WARNING")
        log_event(message, "WARNING")

        # Add specific response based on attack type
        if attack_type == "port_scan":
            # Block IP for 1 hour for port scanning
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
            )
            subprocess.run(
                ["at", "now + 1 hour", "-f", f"iptables -D INPUT -s {ip} -j DROP"],
                check=True,
            )
        elif attack_type in ["syn_flood", "dos"]:
            # Rate limit the IP
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    ip,
                    "-m",
                    "limit",
                    "--limit",
                    "5/min",
                    "--limit-burst",
                    "10",
                    "-j",
                    "ACCEPT",
                ],
                check=True,
            )
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
            )

        add_blocked_ip(ip)


def get_default_interface():
    gateways = netifaces.gateways()
    default = gateways.get("default", {}).get(netifaces.AF_INET)
    if default:
        return default[1]

    # Fallback to first non-loopback interface
    for iface in netifaces.interfaces():
        if iface != "lo":
            return iface
    return "eth0"  # Last resort default


_stop_event = Event()
_ids_thread = None
_packet_inspector = PacketInspector()


def _run_ips():
    interface = get_default_interface()
    log_event(f"IPS scanning started on interface {interface}", "INFO")
    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-n", "-l", "--immediate-mode"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        log_event("Packet capture started", "INFO")
        while not _stop_event.is_set():
            line = process.stdout.readline()
            if not line:
                break

            # Parse IP addresses
            ip_match = re.search(
                r"IP (\d+\.\d+\.\d+\.\d+)[. ].*?> (\d+\.\d+\.\d+\.\d+)", line
            )
            if ip_match:
                src_ip = ip_match.group(1)
                dst_ip = ip_match.group(2)

                # Analyze packet
                result = _packet_inspector.inspect_packet(line, src_ip)
                if result:
                    log_event(result, "WARNING")

        process.terminate()
    except subprocess.CalledProcessError as e:
        log_event(f"IPS error: Failed to start packet capture: {str(e)}", "ERROR")
    except Exception as e:
        log_event(f"IPS error: Unexpected error: {str(e)}", "ERROR")
    finally:
        log_event("IPS stopped", "INFO")


def enable_ids_ips():
    """Enable IDS/IPS functionality"""
    global _ids_thread
    try:
        if _ids_thread is None or not _ids_thread.is_alive():
            _stop_event.clear()
            _ids_thread = Thread(target=_run_ips, daemon=True)
            _ids_thread.start()

        set_feature_state("ids_ips_enabled", True)
        log_event("IDS/IPS enabled", "INFO")
        print("[*] IDS/IPS enabled successfully.")
        return True
    except Exception as e:
        log_event(f"Failed to enable IDS/IPS: {str(e)}", "ERROR")
        return False


def disable_ids_ips():
    """Disable IDS/IPS functionality"""
    global _ids_thread
    try:
        # Signal the thread to stop
        _stop_event.set()

        # Wait for the thread to finish if it's running
        if _ids_thread and _ids_thread.is_alive():
            _ids_thread.join(timeout=2)  # Wait up to 2 seconds

        _ids_thread = None
        set_feature_state("ids_ips_enabled", False)
        log_event("IDS/IPS disabled", "WARNING")
        print("[*] IDS/IPS disabled.")
        return True
    except Exception as e:
        log_event(f"Failed to disable IDS/IPS: {str(e)}", "ERROR")
        return False


def record_failed_login(ip):
    """Record a failed login attempt for IDS analysis"""
    return _packet_inspector.record_failed_auth(ip)


def is_suspicious_ip(ip):
    """Check if an IP address is suspicious based on known patterns"""
    # Check if IP is in known malicious ranges
    suspicious_ranges = [
        "185.0.0.0/8",  # Known for hosting malicious content
        "194.0.0.0/8",  # Common source of attacks
        "45.0.0.0/8",  # Often used in botnets
    ]

    for ip_range in suspicious_ranges:
        if ip_in_network(ip, ip_range):
            return True
    return False


def analyze_packet(packet):
    """Analyze a packet for potential threats"""
    if IP in packet:
        src_ip = packet[IP].src
        # Remove unused dst_ip variable
        if is_suspicious_ip(src_ip):
            add_alert(f"Suspicious traffic from {src_ip}", "WARNING")
            log_event(f"Suspicious traffic from {src_ip}", "WARNING")
            return True
    return False
