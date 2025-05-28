import os
import subprocess
from collections import defaultdict
from firewall.logging import log_event
from .config_manager import set_feature_state, get_feature_state

CONNECTION_LOG_FILE = os.path.join(os.path.dirname(__file__), '../logs/connection.log')

def read_connection_log():
    counts = defaultdict(int)
    if not os.path.exists(CONNECTION_LOG_FILE):
        return counts
    try:
        with open(CONNECTION_LOG_FILE, 'r') as f:
            for line in f:
                ip, count = line.strip().split()
                counts[ip] = int(count)
    except Exception as e:
        log_event(f"Error reading connection log: {e}", level="ERROR")
    return counts

def write_connection_log(counts):
    try:
        with open(CONNECTION_LOG_FILE, 'w') as f:
            for ip, count in counts.items():
                f.write(f"{ip} {count}\n")
    except Exception as e:
        log_event(f"Error writing connection log: {e}", level="ERROR")

def detect_syn_flood(packet):
    return packet.get("flags") == "SYN"

def detect_icmp_flood(packet):
    return packet.get("protocol") == "ICMP"

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
    subprocess.call(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "limit", "--limit", "1/s", "--limit-burst", "3", "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"])

def protect_against_icmp_flood():
    subprocess.call(["iptables", "-A", "INPUT", "-p", "icmp", "-m", "limit", "--limit", "1/s", "--limit-burst", "5", "-j", "ACCEPT"])
    subprocess.call(["iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"])

def limit_connection_rate():
    subprocess.call(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-m", "connlimit", "--connlimit-above", "20", "-j", "REJECT"])

def enable_dos_protection():
    """Enable DoS protection"""
    try:
        set_feature_state("dos_protection_enabled", True)
        log_event("DoS protection enabled", "INFO")
        print("[*] DoS protection enabled.")
        protect_against_syn_flood()
        protect_against_icmp_flood()
        limit_connection_rate()
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
        subprocess.call(["iptables", "-F", "INPUT"])
        return True
    except Exception as e:
        log_event(f"Failed to disable DoS protection: {str(e)}", "ERROR")
        return False

def view_connection_logs(lines=30):
    if not os.path.exists(CONNECTION_LOG_FILE):
        return "[!] No connection logs found."
    try:
        with open(CONNECTION_LOG_FILE, 'r') as f:
            log_lines = f.readlines()
        return "".join(log_lines[-lines:])
    except Exception as e:
        return f"[!] Failed to read connection log: {e}"

def clear_connection_logs():
    try:
        if os.path.exists(CONNECTION_LOG_FILE):
            open(CONNECTION_LOG_FILE, 'w').close()
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
    "clear_connection_logs"
]
