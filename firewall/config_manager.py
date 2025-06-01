import json
import os
from firewall.logging import log_event

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')

DEFAULT_CONFIG = {
    "allowed_ips": [],
    "blocked_ips": [],
    "blocked_ports": [],
    "firewall_enabled": True,
    "dos_protection_enabled": False,
    "ids_ips_enabled": False,
    "nat_enabled": False,
    "stateful_enabled": False,
    "nat_config": {
        "external_interface": "",
        "internal_interface": "",
        "internal_network": ""
    }
}

def load_config():
    """
    Load configuration from file or create with defaults if it doesn't exist.
    
    Returns:
        dict: The configuration dictionary
    """
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Ensure all default keys exist
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
        else:
            config = DEFAULT_CONFIG.copy()
            save_config(config)
        return config
    except Exception as e:
        log_event(f"Error loading config: {str(e)}", "ERROR")
        return DEFAULT_CONFIG.copy()

def save_config(config):
    """
    Save configuration to file.
    
    Args:
        config (dict): Configuration dictionary to save
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        log_event(f"Error saving config: {str(e)}", "ERROR")
        return False

def update_config(key, value):
    """
    Update a specific configuration key.
    
    Args:
        key (str): Configuration key to update
        value: New value for the key
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        config = load_config()
        config[key] = value
        return save_config(config)
    except Exception as e:
        log_event(f"Error updating config: {str(e)}", "ERROR")
        return False

def reset_config():
    """
    Reset configuration to defaults.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        return save_config(DEFAULT_CONFIG.copy())
    except Exception as e:
        log_event(f"Error resetting config: {str(e)}", "ERROR")
        return False

def set_nat_config(external_interface, internal_interface, internal_network):
    """
    Set NAT configuration parameters.
    
    Args:
        external_interface (str): Name of the external network interface
        internal_interface (str): Name of the internal network interface
        internal_network (str): Internal network CIDR notation
    
    Returns:
        bool: True if successful, False otherwise
    """
    config = load_config()
    config["nat_config"] = {
        "external_interface": external_interface,
        "internal_interface": internal_interface,
        "internal_network": internal_network
    }
    return save_config(config)

def get_nat_config():
    """
    Get NAT configuration parameters.
    
    Returns:
        dict: NAT configuration dictionary
    """
    config = load_config()
    return config.get("nat_config", DEFAULT_CONFIG["nat_config"])

def add_allowed_ip(ip):
    config = load_config()
    if ip not in config["allowed_ips"]:
        config["allowed_ips"].append(ip)
        save_config(config)
        return True
    return False

def add_blocked_ip(ip):
    config = load_config()
    if "blocked_ips" not in config:
        config["blocked_ips"] = []
    if ip not in config["blocked_ips"]:
        config["blocked_ips"].append(ip)
        save_config(config)
        return True
    return False

def add_blocked_port(port):
    config = load_config()
    if port not in config["blocked_ports"]:
        config["blocked_ports"].append(port)
        save_config(config)
        return True
    return False

def set_feature_state(feature_name, enabled):
    config = load_config()
    config[feature_name] = enabled
    save_config(config)
    return True

def get_feature_state(feature_name):
    config = load_config()
    return config.get(feature_name, False) 