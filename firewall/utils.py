import ipaddress
import subprocess
from .logging import log_event


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def run_command(cmd):
    """Run a shell command and return True if successful"""
    try:
        subprocess.run(cmd.split(), check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def enable_ip_forwarding():
    """Enable IP forwarding"""
    try:
        result = run_command("sysctl -w net.ipv4.ip_forward=1")
        if result:
            log_event("IP forwarding enabled", "INFO")
        return result
    except Exception:
        return False


def disable_ip_forwarding():
    """Disable IP forwarding"""
    try:
        result = run_command("sysctl -w net.ipv4.ip_forward=0")
        if result:
            log_event("IP forwarding disabled", "WARNING")
        return result
    except Exception:
        return False
