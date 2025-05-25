import os
import subprocess
import logging

LOG_DIR = os.path.join(os.path.dirname(__file__), '../logs')
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, 'firewall.log')
CONNECTION_LOG_FILE = os.path.join(LOG_DIR, 'connection.log')

logger = logging.getLogger("BaselFirewall")
logger.setLevel(logging.DEBUG)

if logger.hasHandlers():
    logger.handlers.clear()

file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_event(message, level="INFO"):
    level = level.upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        level = "INFO"
    getattr(logger, level.lower())(message)

def rule_exists(rule):
    check_rule = ["iptables", "-C"] + rule[1:]
    result = subprocess.run(check_rule, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def enable_logging_rules():
    print("[+] Adding iptables logging rules...")
    rules = [
        ["iptables", "-A", "INPUT", "-j", "LOG", "--log-prefix", "DROP_INPUT: ", "--log-level", "4"],
        ["iptables", "-A", "FORWARD", "-j", "LOG", "--log-prefix", "DROP_FORWARD: ", "--log-level", "4"],
        ["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "LOG", "--log-prefix", "PING_OUT: ", "--log-level", "4"]
    ]
    for rule in rules:
        if rule_exists(rule):
            log_event(f"Iptables logging rule already exists: {' '.join(rule)}", level="DEBUG")
            continue
        try:
            subprocess.run(rule, check=True)
            log_event(f"Iptables logging rule added: {' '.join(rule)}")
        except subprocess.CalledProcessError:
            log_event(f"Failed to apply iptables rule: {' '.join(rule)}", level="ERROR")
            print(f"[-] Failed to apply rule: {' '.join(rule)}")

def show_iptables_logs(keyword="DROP_", lines=30):
    try:
        logs = subprocess.check_output(
            ["journalctl", "-k", "-g", keyword, "--no-pager", "-n", str(lines)],
            stderr=subprocess.STDOUT,
            text=True
        )
        return logs
    except subprocess.CalledProcessError:
        try:
            logs = subprocess.check_output(["dmesg", "-T"], text=True)
            filtered_logs = '\n'.join(line for line in logs.splitlines() if keyword in line)
            return filtered_logs
        except Exception as e:
            return f"[!] Failed to retrieve logs: {str(e)}"
    except Exception as e:
        return f"[!] Unexpected error: {str(e)}"

def view_logs():
    try:
        with open(LOG_FILE, 'r') as f:
            firewall_logs = f.read()
    except FileNotFoundError:
        firewall_logs = "[!] No firewall logs found."
    except PermissionError:
        firewall_logs = "[!] Permission denied reading firewall logs."

    try:
        with open(CONNECTION_LOG_FILE, 'r') as f:
            connection_logs = f.read()
    except FileNotFoundError:
        connection_logs = "[!] No connection logs found."
    except PermissionError:
        connection_logs = "[!] Permission denied reading connection logs."

    iptables_logs = show_iptables_logs()

    return (
        "=== Firewall Logs ===\n" + firewall_logs +
        "\n\n=== Connection Logs ===\n" + connection_logs +
        "\n\n=== IPTables Logs (Last 30 entries) ===\n" + iptables_logs
    )

def clear_logs():
    errors = []
    try:
        with open(LOG_FILE, 'w') as f:
            f.truncate(0)
        log_event("Firewall log file cleared.", level="INFO")
    except Exception as e:
        errors.append(f"Failed to clear firewall log: {str(e)}")
        log_event(errors[-1], level="ERROR")

    try:
        with open(CONNECTION_LOG_FILE, 'w') as f:
            f.truncate(0)
        log_event("Connection log file cleared.", level="INFO")
    except Exception as e:
        errors.append(f"Failed to clear connection log: {str(e)}")
        log_event(errors[-1], level="ERROR")

    if errors:
        return "\n".join(errors)
    else:
        return "[+] All logs cleared."
