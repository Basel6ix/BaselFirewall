import subprocess
import time
from collections import defaultdict
from firewall.config_manager import load_config, save_config
from firewall.logging import log_event

class ConnectionTracker:
    def __init__(self):
        self.connections = defaultdict(lambda: {
            'count': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'states': defaultdict(int)
        })
        self.config = self._load_stateful_config()
    
    def _load_stateful_config(self):
        config = load_config()
        if 'stateful_config' not in config:
            config['stateful_config'] = {
                'max_conn_per_ip': 100,
                'conn_rate_limit': '50/s',
                'icmp_rate_limit': '5/s',
                'icmp_burst': '10',
                'tcp_strict_mode': True,
                'udp_timeout': 30,
                'icmp_timeout': 5
            }
            save_config(config)
        return config['stateful_config']
    
    def track_connection(self, src_ip, protocol, state):
        now = time.time()
        conn = self.connections[src_ip]
        conn['count'] += 1
        conn['last_seen'] = now
        conn['states'][state] += 1
        
        # Check for suspicious activity
        if self._is_suspicious(src_ip, protocol):
            log_event(f"Suspicious activity detected from {src_ip} ({protocol})", "WARNING")
            return True
        return False
    
    def _is_suspicious(self, ip, protocol):
        conn = self.connections[ip]
        now = time.time()
        
        # Check connection rate
        if conn['count'] > self.config['max_conn_per_ip']:
            return True
        
        # Check for rapid connection attempts
        if (now - conn['first_seen']) < 1 and conn['count'] > 20:
            return True
        
        # Protocol-specific checks
        if protocol == 'icmp' and conn['states']['NEW'] > self.config['icmp_burst']:
            return True
        
        return False
    
    def cleanup_old_connections(self):
        now = time.time()
        for ip in list(self.connections.keys()):
            conn = self.connections[ip]
            if now - conn['last_seen'] > self.config['udp_timeout']:
                del self.connections[ip]

def rule_exists(rule):
    result = subprocess.run(
        ["iptables", "-C"] + rule,
        capture_output=True
    )
    return result.returncode == 0

def enable_stateful_inspection_rules():
    print("[+] Enabling enhanced stateful inspection rules...")
    config = load_config().get('stateful_config', {})
    
    rules = [
        # Basic stateful rules
        [
            "INPUT", "-m", "state", "--state",
            "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ],
        # TCP SYN protection
        [
            "INPUT", "-p", "tcp", "--syn", "-m", "state",
            "--state", "NEW", "-m", "limit",
            "--limit", config.get('conn_rate_limit', '50/s'),
            "-j", "ACCEPT"
        ],
        # ICMP flood protection
        [
            "INPUT", "-p", "icmp", "-m", "state",
            "--state", "NEW", "-m", "limit",
            "--limit", config.get('icmp_rate_limit', '5/s'),
            "--limit-burst", config.get('icmp_burst', '10'),
            "-j", "ACCEPT"
        ],
        # Invalid packet protection
        [
            "INPUT", "-m", "state", "--state", "INVALID",
            "-j", "DROP"
        ],
        # Fragment protection
        [
            "INPUT", "-f", "-j", "DROP"
        ]
    ]
    
    success = True
    for rule in rules:
        if not rule_exists(rule):
            try:
                subprocess.run(
                    ["iptables", "-A"] + rule,
                    check=True
                )
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to add rule: {e}")
                success = False
                break
    
    if success:
        print("[+] Enhanced stateful inspection enabled.")
        # Initialize connection tracker
        global connection_tracker
        connection_tracker = ConnectionTracker()
        return True
    else:
        print("[-] Failed to enable all stateful inspection rules.")
        return False

def disable_stateful_inspection_rules():
    print("[+] Disabling stateful inspection rules...")
    rules = [
        [
            "INPUT", "-m", "state", "--state",
            "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ],
        [
            "INPUT", "-p", "tcp", "--syn", "-m", "state",
            "--state", "NEW", "-m", "limit",
            "--limit", "50/s", "-j", "ACCEPT"
        ],
        [
            "INPUT", "-p", "icmp", "-m", "state",
            "--state", "NEW", "-m", "limit",
            "--limit", "5/s", "--limit-burst", "10",
            "-j", "ACCEPT"
        ],
        [
            "INPUT", "-m", "state", "--state", "INVALID",
            "-j", "DROP"
        ],
        [
            "INPUT", "-f", "-j", "DROP"
        ]
    ]
    
    for rule in rules:
        try:
            # Try to remove the rule, but don't raise an error if it doesn't exist
            subprocess.run(
                ["iptables", "-D"] + rule,
                check=False,
                stderr=subprocess.PIPE
            )
        except Exception as e:
            print(f"[-] Error while removing rule: {e}")
    
    print("[+] Stateful inspection disabled.")
    return True

def enable_stateful_inspection():
    success = enable_stateful_inspection_rules()
    if success:
        config = load_config()
        config["stateful_enabled"] = True
        save_config(config)
    return success

def disable_stateful_inspection():
    success = disable_stateful_inspection_rules()
    if success:
        config = load_config()
        config["stateful_enabled"] = False
        save_config(config)
    return success

# Initialize global connection tracker
connection_tracker = None
