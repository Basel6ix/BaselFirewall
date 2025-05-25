import subprocess
from firewall.logging import log_event
from firewall.config_manager import get_nat_config, set_feature_state, get_feature_state
from firewall.utils import enable_ip_forwarding, disable_ip_forwarding

def enable_nat():
    """Enable NAT functionality"""
    try:
        external_iface, internal_iface, internal_network = get_nat_config()
        if not all([external_iface, internal_iface, internal_network]):
            log_event("Failed to enable NAT: Missing interface configuration", "ERROR")
            return False

        enable_ip_forwarding()
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", external_iface, "-j", "MASQUERADE"])
        subprocess.run(["iptables", "-A", "FORWARD", "-i", internal_iface, "-o", external_iface, "-j", "ACCEPT"])
        subprocess.run(["iptables", "-A", "FORWARD", "-i", external_iface, "-o", internal_iface, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        
        set_feature_state("nat_enabled", True)
        log_event("NAT enabled", "INFO")
        print("[*] NAT enabled.")
        return True
    except Exception as e:
        log_event(f"Failed to enable NAT: {str(e)}", "ERROR")
        return False

def disable_nat():
    """Disable NAT functionality"""
    try:
        disable_ip_forwarding()
        subprocess.run(["iptables", "-t", "nat", "-F", "POSTROUTING"])
        subprocess.run(["iptables", "-F", "FORWARD"])
        
        set_feature_state("nat_enabled", False)
        log_event("NAT disabled", "WARNING")
        print("[*] NAT disabled.")
        return True
    except Exception as e:
        log_event(f"Failed to disable NAT: {str(e)}", "ERROR")
        return False
