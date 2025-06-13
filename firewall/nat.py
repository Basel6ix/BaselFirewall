import subprocess
import os
from firewall.config_manager import (
    load_config,
    save_config,
    get_nat_config,
    set_nat_config,
)
from firewall.logging import log_event


def is_interface_valid(interface):
    """Check if a network interface exists"""
    try:
        return os.path.exists(f"/sys/class/net/{interface}")
    except Exception:
        return False


def enable_nat():
    """
    Enable NAT functionality with the configured interfaces.

    Returns:
        bool: True if NAT was successfully enabled, False otherwise
    """
    try:
        nat_config = get_nat_config()
        ext_iface = nat_config["external_interface"]
        int_iface = nat_config["internal_interface"]
        int_network = nat_config["internal_network"]

        # Validate configuration
        if not all([ext_iface, int_iface, int_network]):
            raise ValueError("Missing interface configuration")

        if not all(is_interface_valid(iface) for iface in [ext_iface, int_iface]):
            raise ValueError("Invalid interface specified")

        # Enable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")

        # Clear existing NAT rules
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)

        # Set up NAT rules
        subprocess.run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                ext_iface,
                "-s",
                int_network,
                "-j",
                "MASQUERADE",
            ],
            check=True,
        )

        # Allow forwarding between interfaces
        subprocess.run(
            [
                "iptables",
                "-A",
                "FORWARD",
                "-i",
                int_iface,
                "-o",
                ext_iface,
                "-j",
                "ACCEPT",
            ],
            check=True,
        )

        subprocess.run(
            [
                "iptables",
                "-A",
                "FORWARD",
                "-i",
                ext_iface,
                "-o",
                int_iface,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            check=True,
        )

        # Update config
        config = load_config()
        config["nat_enabled"] = True
        save_config(config)

        log_event("NAT enabled successfully", "INFO")
        return True

    except Exception as e:
        log_event(f"Failed to enable NAT: {str(e)}", "ERROR")
        return False


def disable_nat():
    """
    Disable NAT functionality.

    Returns:
        bool: True if NAT was successfully disabled, False otherwise
    """
    try:
        # Disable IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")

        # Clear NAT rules
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)

        # Remove forwarding rules
        subprocess.run(["iptables", "-F", "FORWARD"], check=True)

        # Update config
        config = load_config()
        config["nat_enabled"] = False
        save_config(config)

        log_event("NAT disabled", "WARNING")
        print("net.ipv4.ip_forward = 0")
        return True

    except Exception as e:
        log_event(f"Failed to disable NAT: {str(e)}", "ERROR")
        return False


def configure_nat(external_interface, internal_interface, internal_network):
    """
    Configure NAT settings.

    Args:
        external_interface (str): Name of the external network interface
        internal_interface (str): Name of the internal network interface
        internal_network (str): Internal network in CIDR notation

    Returns:
        bool: True if configuration was successful, False otherwise
    """
    try:
        # Validate interfaces
        if not all(
            is_interface_valid(iface)
            for iface in [external_interface, internal_interface]
        ):
            raise ValueError("Invalid interface specified")

        # Save configuration
        if set_nat_config(external_interface, internal_interface, internal_network):
            log_event("NAT configuration updated", "INFO")
            return True
        return False

    except Exception as e:
        log_event(f"Failed to configure NAT: {str(e)}", "ERROR")
        return False
