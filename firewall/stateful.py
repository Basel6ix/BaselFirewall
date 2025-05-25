import subprocess
from firewall.config_manager import load_config, save_config

def rule_exists():
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        capture_output=True
    )
    return result.returncode == 0

def enable_stateful_inspection_rules():
    print("[+] Enabling stateful inspection rules...")
    if not rule_exists():
        try:
            subprocess.run([
                "iptables", "-I", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], check=True)
            print("[+] Stateful inspection enabled.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to enable stateful inspection: {e}")
            return False
    else:
        print("[*] Stateful inspection rule already exists, skipping.")
        return True

def disable_stateful_inspection_rules():
    print("[+] Disabling stateful inspection rules...")
    if rule_exists():
        try:
            subprocess.run([
                "iptables", "-D", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], check=True)
            print("[+] Stateful inspection disabled.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to disable stateful inspection: {e}")
            return False
    else:
        print("[*] Stateful inspection rule not found, nothing to delete.")
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
