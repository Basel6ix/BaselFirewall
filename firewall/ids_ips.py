import time
import subprocess
import re
import socket
import netifaces
from collections import defaultdict
from threading import Thread, Event, Lock
from firewall.config_manager import add_blocked_ip, load_config, save_config, set_feature_state, get_feature_state
from firewall.alerts import add_alert
from firewall.logging import log_event

class PacketInspector:
    def __init__(self):
        self.suspicious_ips = defaultdict(lambda: {
            "count": 0,
            "first_seen": time.time(),
            "alerted": False,
            "syn_count": 0,
            "last_syn": 0,
            "failed_auth": 0
        })
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
                "failed_auth_window": 60
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

            # Check for SYN flood
            if "SYN" in packet:
                if now - data["last_syn"] > self.config["syn_flood_window"]:
                    data["syn_count"] = 0
                data["syn_count"] += 1
                data["last_syn"] = now

                if data["syn_count"] > self.config["syn_flood_threshold"] and not data["alerted"]:
                    data["alerted"] = True
                    message = f"ALERT: SYN flood attack detected from {ip}"
                    self._handle_threat(ip, message)
                    return message

            # Check for DoS
            if data["count"] > self.config["dos_threshold"] and not data["alerted"]:
                data["alerted"] = True
                message = f"ALERT: Possible DoS attack from {ip}"
                self._handle_threat(ip, message)
                return message

            return None

    def record_failed_auth(self, ip):
        with self.lock:
            now = time.time()
            data = self.suspicious_ips[ip]
            
            if now - data.get("last_failed_auth", 0) > self.config["failed_auth_window"]:
                data["failed_auth"] = 0
            
            data["failed_auth"] += 1
            data["last_failed_auth"] = now

            if data["failed_auth"] >= self.config["failed_auth_threshold"] and not data["alerted"]:
                data["alerted"] = True
                message = f"ALERT: Multiple failed authentication attempts from {ip}"
                self._handle_threat(ip, message)
                return message

            return None

    def _handle_threat(self, ip, message):
        print(message)
        add_alert(message, "WARNING")
        log_event(message, "WARNING")
        add_blocked_ip(ip)
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

def get_default_interface():
    gateways = netifaces.gateways()
    default = gateways.get('default', {}).get(netifaces.AF_INET)
    if default:
        return default[1]
    
    # Fallback to first non-loopback interface
    for iface in netifaces.interfaces():
        if iface != 'lo':
            return iface
    return 'eth0'  # Last resort default

_stop_event = Event()
_ids_thread = None
_packet_inspector = PacketInspector()

def _run_ips():
    interface = get_default_interface()
    print(f"[*] IPS scanning started on interface {interface}...")
    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-n", "-l", "--immediate-mode"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        
        while not _stop_event.is_set():
            line = process.stdout.readline()
            if not line:
                break

            # Parse IP addresses
            ip_match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)[. ].*?> (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                src_ip = ip_match.group(1)
                dst_ip = ip_match.group(2)
                
                # Analyze packet
                _packet_inspector.inspect_packet(line, src_ip)

        process.terminate()
    except Exception as e:
        log_event(f"IPS error: {str(e)}", "ERROR")
        print(f"[ERROR] IPS encountered an error: {e}")
    finally:
        print("[*] IPS stopped.")

def enable_ids_ips():
    """Enable IDS/IPS functionality"""
    print("[*] IPS scanning started on interface eth0...")
    set_feature_state("ids_ips_enabled", True)
    log_event("IDS/IPS enabled", "INFO")
    print("[*] IDS/IPS enabled successfully.")

def disable_ids_ips():
    """Disable IDS/IPS functionality"""
    set_feature_state("ids_ips_enabled", False)
    log_event("IDS/IPS disabled", "WARNING")
    print("[*] IDS/IPS disabled.")

def record_failed_login(ip):
    """Record a failed login attempt for IDS analysis"""
    return _packet_inspector.record_failed_auth(ip)
