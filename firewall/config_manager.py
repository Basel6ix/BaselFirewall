import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {
            "allowed_ips": [],
            "blocked_ports": [],
            "blocked_ips": [],
            "external_interface": None,
            "internal_interface": None,
            "internal_network": None,
            "ids_ips_enabled": False,
            "dos_protection_enabled": False,
            "nat_enabled": False,
            "stateful_enabled": False
        }
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        # Ensure all required fields exist
        default_fields = {
            "ids_ips_enabled": False,
            "dos_protection_enabled": False,
            "nat_enabled": False,
            "stateful_enabled": False
        }
        for key, value in default_fields.items():
            if key not in config:
                config[key] = value
        return config

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def reset_config():
    default_config = {
        "allowed_ips": [],
        "blocked_ports": [],
        "blocked_ips": [],
        "external_interface": None,
        "internal_interface": None,
        "internal_network": None,
        "ids_ips_enabled": False,
        "dos_protection_enabled": False,
        "nat_enabled": False,
        "stateful_enabled": False
    }
    save_config(default_config)

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

def add_blocked_port(port):
    config = load_config()
    if port not in config["blocked_ports"]:
        config["blocked_ports"].append(port)
        save_config(config)
        return True
    return False

def get_nat_config():
    cfg = load_config()
    return (cfg.get("external_interface"), 
            cfg.get("internal_interface"), 
            cfg.get("internal_network"))

def set_nat_config(external_iface, internal_iface, internal_network):
    cfg = load_config()
    cfg["external_interface"] = external_iface
    cfg["internal_interface"] = internal_iface
    cfg["internal_network"] = internal_network
    save_config(cfg)
    return True

def set_feature_state(feature_name, enabled):
    config = load_config()
    config[feature_name] = enabled
    save_config(config)
    return True

def get_feature_state(feature_name):
    config = load_config()
    return config.get(feature_name, False)
