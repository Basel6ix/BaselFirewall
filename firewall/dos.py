import os
import subprocess
from collections import defaultdict
from firewall.logging import log_event
from .config_manager import set_feature_state, get_feature_state, load_config, save_config
import time
import logging
from scapy.all import IP, TCP, UDP, ICMP

CONNECTION_LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/connection.log")
DOS_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "../config/dos_config.json")


def load_dos_config():
    config = load_config()
    if "dos_config" not in config:
        config["dos_config"] = {
            "syn_flood_limit": "10/s",
            "syn_flood_burst": "20",
            "icmp_flood_limit": "5/s",
            "icmp_flood_burst": "10",
            "connection_limit": "50",
            "tcp_conn_per_ip": "20",
            "monitoring_window": 60,  # seconds
            "alert_threshold": 1000,  # packets
        }
        save_config(config)
    return config["dos_config"]


def read_connection_log():
    counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})
    if not os.path.exists(CONNECTION_LOG_FILE):
        return counts
    try:
        with open(CONNECTION_LOG_FILE, "r") as f:
            for line in f:
                try:
                    ip, count, timestamp = line.strip().split()
                    counts[ip] = {"count": int(count), "timestamp": float(timestamp)}
                except ValueError:
                    continue
    except Exception as e:
        log_event(f"Error reading connection log: {e}", level="ERROR")
    return counts


def write_connection_log(counts):
    try:
        with open(CONNECTION_LOG_FILE, "w") as f:
            for ip, data in counts.items():
                f.write(f"{ip} {data['count']} {data['timestamp']}\n")
    except Exception as e:
        log_event(f"Error writing connection log: {e}", level="ERROR")


def detect_syn_flood(packet):
    """
    Enhanced SYN flood detection specifically for hping3 attacks
    """
    if packet.get("flags") == "SYN":
        src_ip = packet.get("src")
        now = time.time()
        counts = read_connection_log()
        
        if src_ip not in counts:
            counts[src_ip] = {
                'syn_count': 0,
                'last_syn': 0,
                'alert_sent': False,
                'first_syn': now
            }
        
        data = counts[src_ip]
        
        # Reset counter if more than 1 second has passed
        if now - data['last_syn'] > 1:
            data['syn_count'] = 0
            data['first_syn'] = now
            data['alert_sent'] = False
        
        data['syn_count'] += 1
        data['last_syn'] = now
        
        # Calculate rate
        duration = now - data['first_syn']
        if duration > 0:
            rate = data['syn_count'] / duration
            
            # Alert if rate exceeds threshold (typical for hping3 --flood)
            if rate > 100 and not data['alert_sent']:  # More than 100 SYN/s
                message = (
                    f"ALERT: SYN flood attack detected from {src_ip} "
                    f"(Rate: {rate:.1f} SYN/s)"
                )
                log_event(message, "WARNING")
                add_alert(message, "WARNING")
                data['alert_sent'] = True
                
                # Add temporary block
                try:
                    subprocess.run([
                        "iptables", "-A", "INPUT",
                        "-s", src_ip,
                        "-j", "DROP"
                    ], check=True)
                    
                    # Remove block after 5 minutes
                    unblock_cmd = f"iptables -D INPUT -s {src_ip} -j DROP"
                    subprocess.run([
                        "at", "now", "+", "5", "minutes"
                    ], input=unblock_cmd.encode(), check=True)
                    
                except subprocess.CalledProcessError as e:
                    log_event(f"Failed to block SYN flood attacker: {e}", "ERROR")
                
                return True
        
        write_connection_log(counts)
    return False


def detect_icmp_flood(packet):
    """
    Enhanced ICMP flood detection with specific rate monitoring
    """
    if packet.get("protocol") == "ICMP":
        src_ip = packet.get("src")
        now = time.time()
        counts = read_connection_log()
        
        if src_ip not in counts:
            counts[src_ip] = {
                'icmp_count': 0,
                'last_icmp': 0,
                'alert_sent': False,
                'first_icmp': now
            }
        
        data = counts[src_ip]
        
        # Reset counter if more than 1 second has passed
        if now - data['last_icmp'] > 1:
            data['icmp_count'] = 0
            data['first_icmp'] = now
            data['alert_sent'] = False
        
        data['icmp_count'] += 1
        data['last_icmp'] = now
        
        # Calculate rate
        duration = now - data['first_icmp']
        if duration > 0:
            rate = data['icmp_count'] / duration
            
            # Alert if rate exceeds threshold (100 packets per second)
            if rate > 100 and not data['alert_sent']:
                message = (
                    f"ALERT: ICMP flood attack detected from {src_ip} "
                    f"(Rate: {rate:.1f} packets/s)"
                )
                log_event(message, "WARNING")
                add_alert(message, "WARNING")
                data['alert_sent'] = True
                
                # Add temporary block
                try:
                    subprocess.run([
                        "iptables", "-A", "INPUT",
                        "-p", "icmp",
                        "-s", src_ip,
                        "-j", "DROP"
                    ], check=True)
                    
                    # Remove block after 5 minutes
                    unblock_cmd = f"iptables -D INPUT -p icmp -s {src_ip} -j DROP"
                    subprocess.run([
                        "at", "now", "+", "5", "minutes"
                    ], input=unblock_cmd.encode(), check=True)
                    
                except subprocess.CalledProcessError as e:
                    log_event(f"Failed to block ICMP flood attacker: {e}", "ERROR")
                
                return True
        
        write_connection_log(counts)
    return False


def is_connection_rate_exceeded(ip, max_connections=20):
    counts = read_connection_log()
    return counts.get(ip, 0) > max_connections


def increment_connection(ip):
    counts = read_connection_log()
    counts[ip] += 1
    write_connection_log(counts)


def reset_connection_counts():
    try:
        if os.path.exists(CONNECTION_LOG_FILE):
            os.remove(CONNECTION_LOG_FILE)
            log_event("Connection log reset.", level="INFO")
    except Exception as e:
        log_event(f"Error resetting connection log: {e}", level="ERROR")


def protect_against_syn_flood():
    """
    Enhanced protection against SYN flood attacks (especially hping3)
    """
    # SYN flood protection with strict rate limiting
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
        "-m", "hashlimit",
        "--hashlimit-name", "synflood",
        "--hashlimit-above", "100/s",
        "--hashlimit-burst", "20",
        "--hashlimit-mode", "srcip",
        "--hashlimit-htable-expire", "300000",
        "-j", "DROP"
    ])
    
    # Add connection tracking limits
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "tcp",
        "-m", "conntrack",
        "--ctstate", "NEW",
        "-m", "limit",
        "--limit", "60/s",
        "-j", "ACCEPT"
    ])
    
    # Drop invalid packets
    subprocess.call([
        "iptables", "-A", "INPUT",
        "-m", "state",
        "--state", "INVALID",
        "-j", "DROP"
    ])
    
    # Log SYN flood attempts
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
        "-m", "hashlimit",
        "--hashlimit-name", "synfloodlog",
        "--hashlimit-above", "100/s",
        "--hashlimit-burst", "20",
        "--hashlimit-mode", "srcip",
        "-j", "LOG",
        "--log-prefix", "SYN_FLOOD: "
    ])


def protect_against_icmp_flood():
    """
    Enhanced ICMP flood protection with specific thresholds
    """
    # Basic ICMP rate limiting
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "icmp",
        "-m", "hashlimit",
        "--hashlimit-name", "icmpflood",
        "--hashlimit-above", "100/s",
        "--hashlimit-burst", "50",
        "--hashlimit-mode", "srcip",
        "--hashlimit-htable-expire", "300000",
        "-j", "DROP"
    ])
    
    # Log ICMP flood attempts
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "icmp",
        "-m", "hashlimit",
        "--hashlimit-name", "icmpfloodlog",
        "--hashlimit-above", "100/s",
        "--hashlimit-burst", "50",
        "--hashlimit-mode", "srcip",
        "-j", "LOG",
        "--log-prefix", "ICMP_FLOOD: "
    ])
    
    # Allow some ICMP for normal operation
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "icmp",
        "-m", "limit",
        "--limit", "30/s",
        "--limit-burst", "20",
        "-j", "ACCEPT"
    ])
    
    # Drop remaining ICMP
    subprocess.call([
        "iptables", "-A", "INPUT",
        "-p", "icmp",
        "-j", "DROP"
    ])


def limit_connection_rate(config):
    # Per-IP connection limits
    subprocess.call([
        "iptables", "-A", "INPUT", "-p", "tcp",
        "-m", "connlimit",
        "--connlimit-above", config["tcp_conn_per_ip"],
        "--connlimit-mask", "32",
        "-j", "REJECT"
    ])
    
    # Global connection limits
    subprocess.call([
        "iptables", "-A", "INPUT",
        "-m", "connlimit",
        "--connlimit-above", config["connection_limit"],
        "-j", "REJECT"
    ])


def enable_dos_protection():
    """Enable DoS protection with advanced monitoring"""
    try:
        config = load_dos_config()
        set_feature_state("dos_protection_enabled", True)
        log_event("Enhanced DoS protection enabled", "INFO")
        print("[*] Enhanced DoS protection enabled with adaptive thresholds.")
        
        protect_against_syn_flood()
        protect_against_icmp_flood()
        limit_connection_rate(config)
        
        # Add connection tracking and state monitoring
        subprocess.call([
            "iptables", "-A", "INPUT",
            "-m", "state",
            "--state", "ESTABLISHED,RELATED",
            "-j", "ACCEPT"
        ])
        
        return True
    except Exception as e:
        log_event(f"Failed to enable DoS protection: {str(e)}", "ERROR")
        return False


def disable_dos_protection():
    """Disable DoS protection"""
    try:
        set_feature_state("dos_protection_enabled", False)
        log_event("DoS protection disabled", "WARNING")
        print("[*] DoS protection disabled.")

        # Remove only DoS-specific rules
        subprocess.call(
            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--syn",
                "-m",
                "limit",
                "--limit",
                "1/s",
                "--limit-burst",
                "3",
                "-j",
                "ACCEPT",
            ]
        )
        subprocess.call(["iptables", "-D", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"])
        subprocess.call(
            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "icmp",
                "-m",
                "limit",
                "--limit",
                "1/s",
                "--limit-burst",
                "5",
                "-j",
                "ACCEPT",
            ]
        )
        subprocess.call(["iptables", "-D", "INPUT", "-p", "icmp", "-j", "DROP"])
        subprocess.call(
            [
                "iptables",
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-m",
                "connlimit",
                "--connlimit-above",
                "20",
                "-j",
                "REJECT",
            ]
        )

        return True
    except Exception as e:
        log_event(f"Failed to disable DoS protection: {str(e)}", "ERROR")
        return False


def view_connection_logs(lines=30):
    if not os.path.exists(CONNECTION_LOG_FILE):
        return "[!] No connection logs found."
    try:
        with open(CONNECTION_LOG_FILE, "r") as f:
            log_lines = f.readlines()
        return "".join(log_lines[-lines:])
    except Exception as e:
        return f"[!] Failed to read connection log: {e}"


def clear_connection_logs():
    try:
        if os.path.exists(CONNECTION_LOG_FILE):
            open(CONNECTION_LOG_FILE, "w").close()
            log_event("Connection log cleared.", level="INFO")
    except Exception as e:
        log_event(f"Failed to clear connection log: {e}", level="ERROR")


__all__ = [
    "detect_syn_flood",
    "detect_icmp_flood",
    "is_connection_rate_exceeded",
    "increment_connection",
    "reset_connection_counts",
    "enable_dos_protection",
    "disable_dos_protection",
    "view_connection_logs",
    "clear_connection_logs",
]
