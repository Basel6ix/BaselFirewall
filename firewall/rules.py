import subprocess
import os
from firewall.config_manager import load_config, save_config
from firewall.stateful import enable_stateful_inspection_rules, disable_stateful_inspection_rules
from firewall.utils import is_valid_ip
from firewall.logging import log_event
from firewall.dos import disable_dos_protection
from firewall.ids_ips import disable_ids_ips
from firewall.nat import disable_nat

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')

def is_valid_port(port):
    try:
        port = int(port)
        return 0 < port < 65536
    except (ValueError, TypeError):
        return False

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        log_event(f"Command failed: {e}", "ERROR")
        return False

def set_default_policy():
    run_command("iptables -P INPUT DROP")
    run_command("iptables -P FORWARD DROP")
    run_command("iptables -P OUTPUT ACCEPT")
    log_event("Default firewall policy set", "INFO")

def apply_essential_rules():
    # Allow established connections
    run_command("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    # Allow loopback
    run_command("iptables -A INPUT -i lo -j ACCEPT")
    # Allow ICMP (ping)
    run_command("iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT")
    run_command("iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT")
    # Allow DNS responses
    run_command("iptables -A INPUT -p udp --sport 53 -j ACCEPT")
    log_event("Essential rules applied", "INFO")

def apply_firewall_rules():
    # Clear existing rules
    run_command("iptables -F")
    
    # Apply rules in order of priority
    apply_essential_rules()
    
    config = load_config()
    
    # High priority: Allowed IPs
    for ip in config.get("allowed_ips", []):
        run_command(f"iptables -A INPUT -s {ip} -j ACCEPT")
        log_event(f"Firewall rule applied: Allow IP {ip}", "INFO")
    
    # Medium priority: Blocked IPs
    for ip in config.get("blocked_ips", []):
        run_command(f"iptables -A INPUT -s {ip} -j DROP")
        log_event(f"Firewall rule applied: Block IP {ip}", "INFO")
    
    # Low priority: Blocked ports
    for port in config.get("blocked_ports", []):
        if is_valid_port(port):
            run_command(f"iptables -A INPUT -p tcp --dport {port} -j DROP")
            run_command(f"iptables -A INPUT -p udp --dport {port} -j DROP")
            log_event(f"Firewall rule applied: Block port {port}", "INFO")
        else:
            log_event(f"Invalid port number ignored: {port}", "WARNING")

def allow_ip(ip):
    if not is_valid_ip(ip):
        log_event(f"Invalid IP address attempt to allow: {ip}", "ERROR")
        return False
    
    config = load_config()
    if ip not in config.get("allowed_ips", []):
        config.setdefault("allowed_ips", []).append(ip)
        if ip in config.get("blocked_ips", []):
            config["blocked_ips"].remove(ip)
            run_command(f"iptables -D INPUT -s {ip} -j DROP")
            log_event(f"Removed IP {ip} from blocked list due to allow_ip", "WARNING")
        save_config(config)
        if run_command(f"iptables -I INPUT 1 -s {ip} -j ACCEPT"):  # Insert at top for priority
            log_event(f"Allowed IP added: {ip}", "INFO")
            return True
    return False

def block_ip(ip):
    if not is_valid_ip(ip):
        log_event(f"Invalid IP address attempt to block: {ip}", "ERROR")
        return False
    
    config = load_config()
    if ip not in config.get("blocked_ips", []):
        config.setdefault("blocked_ips", []).append(ip)
        if ip in config.get("allowed_ips", []):
            config["allowed_ips"].remove(ip)
            run_command(f"iptables -D INPUT -s {ip} -j ACCEPT")
            log_event(f"Removed IP {ip} from allowed list due to block_ip", "WARNING")
        save_config(config)
        if run_command(f"iptables -A INPUT -s {ip} -j DROP"):
            log_event(f"Blocked IP added: {ip}", "INFO")
            return True
    return False

def block_port(port):
    if not is_valid_port(port):
        log_event(f"Invalid port number attempt to block: {port}", "ERROR")
        return False
    
    config = load_config()
    if port not in config.get("blocked_ports", []):
        config.setdefault("blocked_ports", []).append(port)
        save_config(config)
        success = True
        if not run_command(f"iptables -A INPUT -p tcp --dport {port} -j DROP"):
            success = False
        if not run_command(f"iptables -A INPUT -p udp --dport {port} -j DROP"):
            success = False
        if success:
            log_event(f"Blocked port added: {port}", "INFO")
            return True
    return False

def remove_allowed_ip(ip):
    if not is_valid_ip(ip):
        log_event(f"Invalid IP address attempt to remove from allowed: {ip}", "ERROR")
        return False
    
    config = load_config()
    if ip in config.get("allowed_ips", []):
        config["allowed_ips"].remove(ip)
        save_config(config)
        if run_command(f"iptables -D INPUT -s {ip} -j ACCEPT"):
            log_event(f"Allowed IP removed: {ip}", "WARNING")
            return True
    return False

def remove_blocked_ip(ip):
    if not is_valid_ip(ip):
        log_event(f"Invalid IP address attempt to remove from blocked: {ip}", "ERROR")
        return False
    
    config = load_config()
    if ip in config.get("blocked_ips", []):
        config["blocked_ips"].remove(ip)
        save_config(config)
        if run_command(f"iptables -D INPUT -s {ip} -j DROP"):
            log_event(f"Blocked IP removed: {ip}", "WARNING")
            return True
    return False

def remove_blocked_port(port):
    if not is_valid_port(port):
        log_event(f"Invalid port number attempt to remove from blocked: {port}", "ERROR")
        return False
    
    config = load_config()
    if port in config.get("blocked_ports", []):
        config["blocked_ports"].remove(port)
        save_config(config)
        success = True
        if not run_command(f"iptables -D INPUT -p tcp --dport {port} -j DROP"):
            success = False
        if not run_command(f"iptables -D INPUT -p udp --dport {port} -j DROP"):
            success = False
        if success:
            log_event(f"Blocked port removed: {port}", "WARNING")
            return True
    return False

def reset_firewall():
    """
    Reset firewall to default state while preserving configured rules.
    
    This function:
    1. Disables all advanced features
    2. Flushes all chains
    3. Sets default policies
    4. Reapplies saved rules from config
    
    Returns:
        bool: True if reset was successful, False otherwise
    """
    try:
        # Store current configuration
        config = load_config()
        
        # Disable advanced features
        disable_stateful_inspection_rules()
        disable_dos_protection()
        disable_ids_ips()
        disable_nat()
        
        # Flush all rules and user-defined chains
        run_command("iptables -F")
        run_command("iptables -X")
        
        # Set default policies
        set_default_policy()
        
        # Reapply saved rules
        apply_firewall_rules()
        
        log_event("Firewall reset successfully", "INFO")
        return True
        
    except Exception as e:
        log_event(f"Error resetting firewall: {str(e)}", "ERROR")
        return False

def enable_stateful_inspection():
    enable_stateful_inspection_rules()
    log_event("Stateful inspection enabled", "INFO")

def disable_stateful_inspection():
    disable_stateful_inspection_rules()
    log_event("Stateful inspection disabled", "WARNING")

def clear_rules():
    config = load_config()
    config['allowed_ips'] = []
    config['blocked_ips'] = []
    config['blocked_ports'] = []
    save_config(config)
    apply_firewall_rules()  # Reapply rules after clearing
    log_event("All firewall rules cleared", "WARNING")

def disable_firewall():
    """
    Completely disables the firewall by:
    1. Flushing all rules
    2. Setting all chains to ACCEPT
    3. Disabling all protection features
    4. Saving the disabled state in config
    
    Returns:
        bool: True if firewall was successfully disabled, False otherwise
    """
    try:
        # Disable all protection features
        disable_dos_protection()
        disable_ids_ips()
        disable_nat()
        disable_stateful_inspection()
        
        # Flush all rules and delete custom chains
        run_command("iptables -F")  # Flush all rules
        run_command("iptables -X")  # Delete user-defined chains
        
        # Set all default policies to ACCEPT
        run_command("iptables -P INPUT ACCEPT")
        run_command("iptables -P FORWARD ACCEPT")
        run_command("iptables -P OUTPUT ACCEPT")
        
        # Update config to reflect disabled state
        config = load_config()
        config["firewall_enabled"] = False
        save_config(config)
        
        log_event("Firewall completely disabled", "CRITICAL")
        return True
    except Exception as e:
        log_event(f"Failed to disable firewall: {str(e)}", "ERROR")
        return False

def enable_firewall():
    """
    Re-enables the firewall with default configuration.
    
    Returns:
        bool: True if firewall was successfully enabled, False otherwise
    """
    try:
        config = load_config()
        config["firewall_enabled"] = True
        save_config(config)
        
        # Reset to default state
        reset_firewall()
        
        log_event("Firewall re-enabled with default configuration", "CRITICAL")
        return True
    except Exception as e:
        log_event(f"Failed to enable firewall: {str(e)}", "ERROR")
        return False
