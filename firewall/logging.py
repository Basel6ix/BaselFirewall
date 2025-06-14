import os
import subprocess
import logging
import time
from logging.handlers import RotatingFileHandler
from datetime import datetime
import gzip
import shutil

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
CONNECTION_LOG_FILE = os.path.join(LOG_DIR, "connection.log")

# Clear any existing handlers
logging.getLogger().handlers = []

# Setup root logger
logger = logging.getLogger("BaselFirewall")
logger.setLevel(logging.DEBUG)
logger.handlers = []  # Clear any existing handlers
logger.propagate = False  # Prevent propagation to parent loggers

# Setup file handler
file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


def setup_logger(
    name, log_file, level=logging.INFO, max_size=10 * 1024 * 1024, backup_count=5
):
    """Setup a logger with rotation"""
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []  # Clear any existing handlers
    logger.propagate = False  # Prevent propagation to parent loggers

    handler = RotatingFileHandler(log_file, maxBytes=max_size, backupCount=backup_count)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# Setup loggers
firewall_logger = setup_logger("firewall", LOG_FILE)
attack_logger = setup_logger("attacks", os.path.join(LOG_DIR, "attacks.log"))
access_logger = setup_logger("access", os.path.join(LOG_DIR, "access.log"))


def compress_old_logs():
    """Compress log files older than 24 hours"""
    now = time.time()

    for filename in os.listdir(LOG_DIR):
        if filename.endswith(".log"):
            filepath = os.path.join(LOG_DIR, filename)

            # Check if file is older than 24 hours
            if os.path.getmtime(filepath) < (now - 86400):
                try:
                    with open(filepath, "rb") as f_in:
                        with gzip.open(f"{filepath}.gz", "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(filepath)
                except Exception as e:
                    print(f"Error compressing log file {filename}: {e}")


def log_event(message, level="INFO", category="FIREWALL"):
    """
    Enhanced logging with categories and automatic rotation
    """
    try:
        # Compress old logs if needed
        compress_old_logs()

        # Select appropriate logger based on category
        if category == "ATTACK":
            logger = attack_logger
        elif category == "ACCESS":
            logger = access_logger
        else:
            logger = firewall_logger

        # Log with appropriate level
    level = level.upper()
        if level == "DEBUG":
            logger.debug(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "ERROR":
            logger.error(message)
        elif level == "CRITICAL":
            logger.critical(message)
        else:
            logger.info(message)

    except Exception as e:
        print(f"Logging error: {e}")
        # Fallback to basic logging
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} - {level} - {message}\n")


def rule_exists(rule):
    check_rule = ["iptables", "-C"] + rule[1:]
    result = subprocess.run(check_rule, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0


def enable_logging_rules():
    print("[+] Adding iptables logging rules...")
    rules = [
        # Input chain logging
        [
            "iptables",
            "-A",
            "INPUT",
            "-j",
            "LOG",
            "--log-prefix",
            "DROP_INPUT: ",
            "--log-level",
            "4",
        ],
        [
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "state",
            "--state",
            "NEW",
            "-j",
            "LOG",
            "--log-prefix",
            "NEW_CONNECTION: ",
            "--log-level",
            "4",
        ],
        # Forward chain logging
        [
            "iptables",
            "-A",
            "FORWARD",
            "-j",
            "LOG",
            "--log-prefix",
            "DROP_FORWARD: ",
            "--log-level",
            "4",
        ],
        # Output chain logging
        [
            "iptables",
            "-A",
            "OUTPUT",
            "-j",
            "LOG",
            "--log-prefix",
            "DROP_OUTPUT: ",
            "--log-level",
            "4",
        ],
        [
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            "icmp",
            "-j",
            "LOG",
            "--log-prefix",
            "PING_OUT: ",
            "--log-level",
            "4",
        ],
        # Additional security logging
        [
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "ALL",
            "NONE",
            "-j",
            "LOG",
            "--log-prefix",
            "STEALTH_SCAN: ",
            "--log-level",
            "4",
        ],
        [
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "ALL",
            "ALL",
            "-j",
            "LOG",
            "--log-prefix",
            "XMAS_SCAN: ",
            "--log-level",
            "4",
        ],
        [
            "iptables",
            "-A",
            "INPUT",
            "-f",
            "-j",
            "LOG",
            "--log-prefix",
            "FRAGMENT_PACKET: ",
            "--log-level",
            "4",
        ],
    ]

    for rule in rules:
        if rule_exists(rule):
            log_event(
                f"Iptables logging rule already exists: {' '.join(rule)}", level="DEBUG"
            )
            continue
        try:
            subprocess.run(rule, check=True)
            log_event(f"Iptables logging rule added: {' '.join(rule)}")
        except subprocess.CalledProcessError:
            log_event(f"Failed to apply iptables rule: {' '.join(rule)}", level="ERROR")
            print(f"[-] Failed to apply rule: {' '.join(rule)}")


def show_iptables_logs(keyword="", lines=50):
    """Show iptables logs with improved formatting and filtering"""
    try:
        # Try using journalctl first
        if not keyword:
            keyword = "DROP_|NEW_CONNECTION|STEALTH_SCAN|XMAS_SCAN|FRAGMENT_PACKET|PING"

        logs = subprocess.check_output(
            ["journalctl", "-k", "-g", keyword, "--no-pager", "-n", str(lines)],
            stderr=subprocess.STDOUT,
            text=True,
        )
        return format_iptables_logs(logs)
    except subprocess.CalledProcessError:
        try:
            # Fallback to dmesg if journalctl fails
            logs = subprocess.check_output(["dmesg", "-T"], text=True)
            filtered_logs = "\n".join(
                line
                for line in logs.splitlines()
                if any(k in line for k in keyword.split("|"))
            )
            return format_iptables_logs(filtered_logs)
        except Exception as e:
            return f"[!] Failed to retrieve logs: {str(e)}"
    except Exception as e:
        return f"[!] Unexpected error: {str(e)}"


def format_iptables_logs(logs):
    """Format iptables logs for better readability"""
    formatted_logs = []
    for line in logs.splitlines():
        if any(
            prefix in line
            for prefix in [
                "DROP_",
                "NEW_CONNECTION:",
                "STEALTH_SCAN:",
                "XMAS_SCAN:",
                "FRAGMENT_PACKET:",
                "PING_OUT:",
            ]
        ):
            # Extract timestamp and message
            parts = line.split(": ", 1)
            if len(parts) > 1:
                timestamp = parts[0]
                message = parts[1]
                formatted_logs.append(f"{timestamp}\n    {message}\n")
            else:
                formatted_logs.append(line)

    return (
        "\n".join(formatted_logs) if formatted_logs else "[!] No matching logs found."
    )


def view_logs():
    """View all logs with proper formatting"""
    try:
        with open(LOG_FILE, "r") as f:
            firewall_logs = f.readlines()
    except FileNotFoundError:
        firewall_logs = ["[!] No firewall logs found."]
    except PermissionError:
        firewall_logs = ["[!] Permission denied reading firewall logs."]

    try:
        with open(CONNECTION_LOG_FILE, "r") as f:
            connection_logs = f.readlines()
    except FileNotFoundError:
        connection_logs = ["[!] No connection logs found."]
    except PermissionError:
        connection_logs = ["[!] Permission denied reading connection logs."]

    iptables_logs = show_iptables_logs()

    # Format the logs
    formatted_logs = "=== Firewall Logs ===\n"
    for line in firewall_logs:
        line = line.strip()
        if line:
            formatted_logs += line + "\n"

    formatted_logs += "\n=== Connection Logs ===\n"
    for line in connection_logs:
        line = line.strip()
        if line:
            formatted_logs += line + "\n"

    formatted_logs += "\n=== IPTables Logs (Last 30 entries) ===\n"
    formatted_logs += iptables_logs

    return formatted_logs


def clear_logs():
    errors = []
    try:
        with open(LOG_FILE, "w") as f:
            f.truncate(0)
        log_event("Firewall log file cleared.", level="INFO")
    except Exception as e:
        errors.append(f"Failed to clear firewall log: {str(e)}")
        log_event(errors[-1], level="ERROR")

    try:
        with open(CONNECTION_LOG_FILE, "w") as f:
            f.truncate(0)
        log_event("Connection log file cleared.", level="INFO")
    except Exception as e:
        errors.append(f"Failed to clear connection log: {str(e)}")
        log_event(errors[-1], level="ERROR")

    if errors:
        return "\n".join(errors)
    else:
        return "[+] All logs cleared."


def get_recent_logs(log_type="firewall", lines=100):
    """
    Get recent log entries, including from compressed files if needed
    """
    log_file = {
        "firewall": LOG_FILE,
        "attacks": os.path.join(LOG_DIR, "attacks.log"),
        "access": os.path.join(LOG_DIR, "access.log"),
    }.get(log_type.lower(), LOG_FILE)

    log_entries = []

    # Read from current log file
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            log_entries.extend(f.readlines())

    # If we need more entries, check compressed logs
    if len(log_entries) < lines:
        compressed_logs = sorted(
            [f for f in os.listdir(LOG_DIR) if f.endswith(".gz")], reverse=True
        )

        for compressed_log in compressed_logs:
            if len(log_entries) >= lines:
                break

            try:
                with gzip.open(os.path.join(LOG_DIR, compressed_log), "rt") as f:
                    log_entries.extend(f.readlines())
            except Exception as e:
                print(f"Error reading compressed log {compressed_log}: {e}")

    # Return the most recent entries
    return log_entries[-lines:]


def clear_old_logs(days=30):
    """Clear logs older than specified days"""
    now = time.time()
    max_age = days * 86400  # Convert days to seconds

    for filename in os.listdir(LOG_DIR):
        filepath = os.path.join(LOG_DIR, filename)
        if os.path.getmtime(filepath) < (now - max_age):
            try:
                os.remove(filepath)
                print(f"Removed old log file: {filename}")
            except Exception as e:
                print(f"Error removing old log file {filename}: {e}")
