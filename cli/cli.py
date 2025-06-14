import sys 
import os
from colorama import init, Fore, Style
from firewall.auth import (
    authenticate,
    is_admin,
    add_user,
    remove_user,
    list_users,
    log_login_attempt
)
from firewall.rules import (
    allow_ip,
    remove_allowed_ip,
    block_port,
    remove_blocked_port,
    load_config
)
from firewall.config_manager import reset_config, set_nat_config
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.nat import enable_nat, disable_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.logging import log_event, view_logs, clear_logs
from firewall.alerts import add_alert, get_live_alerts
import json

TEMPLATES_FILE = os.path.join(os.path.dirname(__file__), "../config/templates.json")


def load_templates():
    try:
        if os.path.exists(TEMPLATES_FILE):
            with open(TEMPLATES_FILE, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        log_event(f"Error loading templates: {str(e)}", "ERROR")
        return {}


def save_templates(templates):
    try:
        with open(TEMPLATES_FILE, "w") as f:
            json.dump(templates, f, indent=4)
        return True
    except Exception as e:
        log_event(f"Error saving templates: {str(e)}", "ERROR")
        return False


def list_templates_cli():
    templates = load_templates()
    if not templates:
        print("No templates available.")
        return
    print("\nAvailable Templates:")
    for name, config in templates.items():
        print(f"\n{name}:")
        print("  Allowed Ports:", config.get("allowed_ports", []))
        print("  Blocked Ports:", config.get("blocked_ports", []))
        print(
            "  DoS Protection:",
            "Enabled" if config.get("dos_protection_enabled", False) else "Disabled",
        )
        print(
            "  IDS/IPS:",
            "Enabled" if config.get("ids_ips_enabled", False) else "Disabled",
        )
        print(
            "  Stateful Inspection:",
            "Enabled" if config.get("stateful_enabled", False) else "Disabled",
        )


def apply_template_cli():
    templates = load_templates()
    if not templates:
        print("No templates available.")
        return
    
    print("\nAvailable Templates:")
    for i, name in enumerate(templates.keys(), 1):
        print(f"{i}. {name}")
    
    try:
        choice = int(prompt("\nSelect template number to apply: "))
        if 1 <= choice <= len(templates):
            template_name = list(templates.keys())[choice - 1]
            template = templates[template_name]
            
            config = load_config()
            
            # Apply template settings
            config["blocked_ports"] = template.get("blocked_ports", [])
            config["dos_protection_enabled"] = template.get(
                "dos_protection_enabled", False
            )
            config["ids_ips_enabled"] = template.get("ids_ips_enabled", False)
            config["stateful_enabled"] = template.get("stateful_enabled", False)
            
            # Apply allowed ports
            for port in template.get("allowed_ports", []):
                if port not in config["blocked_ports"]:
                    config["blocked_ports"].append(port)
            
            if save_config(config):
                add_alert(f"Applied template: {template_name}", "INFO")
                log_event(f"Applied template: {template_name}", "INFO")
                print(f"\nSuccessfully applied template: {template_name}")
            else:
                print("\nError applying template.")
        else:
            print("\nInvalid template number.")
    except ValueError:
        print("\nInvalid input. Please enter a number.")


def add_template_cli():
    name = prompt("Enter template name: ")
    if not name:
        print("Template name cannot be empty.")
        return
    
    templates = load_templates()
    if name in templates:
        print("Template with this name already exists.")
        return
    
    template = {
        "allowed_ports": [],
        "blocked_ports": [],
        "dos_protection_enabled": True,
        "ids_ips_enabled": True,
        "stateful_enabled": True,
    }
    
    # Get allowed ports
    ports = prompt("Enter allowed ports (comma-separated numbers): ")
    if ports.strip():
        try:
            template["allowed_ports"] = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            print("Invalid port numbers. Using empty list.")
    
    # Get blocked ports
    ports = prompt("Enter blocked ports (comma-separated numbers): ")
    if ports.strip():
        try:
            template["blocked_ports"] = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            print("Invalid port numbers. Using empty list.")
    
    # Get feature states
    template["dos_protection_enabled"] = (
        prompt("Enable DoS protection? (yes/no): ").lower() == "yes"
    )
    template["ids_ips_enabled"] = prompt("Enable IDS/IPS? (yes/no): ").lower() == "yes"
    template["stateful_enabled"] = (
        prompt("Enable stateful inspection? (yes/no): ").lower() == "yes"
    )
    
    templates[name] = template
    if save_templates(templates):
        add_alert(f"Added new template: {name}", "INFO")
        log_event(f"Added new template: {name}", "INFO")
        print(f"\nSuccessfully added template: {name}")
    else:
        print("\nError saving template.")


def delete_template_cli():
    templates = load_templates()
    if not templates:
        print("No templates available.")
        return
    
    print("\nAvailable Templates:")
    for i, name in enumerate(templates.keys(), 1):
        print(f"{i}. {name}")
    
    try:
        choice = int(prompt("\nSelect template number to delete: "))
        if 1 <= choice <= len(templates):
            template_name = list(templates.keys())[choice - 1]
            confirm = prompt(
                f"Are you sure you want to delete template '{template_name}'? (yes/no): "
            )
            if confirm.lower() == "yes":
                del templates[template_name]
                if save_templates(templates):
                    add_alert(f"Deleted template: {template_name}", "INFO")
                    log_event(f"Deleted template: {template_name}", "INFO")
                    print(f"\nSuccessfully deleted template: {template_name}")
                else:
                    print("\nError deleting template.")
            else:
                print("\nTemplate deletion cancelled.")
        else:
            print("\nInvalid template number.")
    except ValueError:
        print("\nInvalid input. Please enter a number.")


def prompt(msg):
    return input(msg).strip()


def login():
    """Handle user login"""
    while True:
        username = prompt("Username: ")
        if not username:
            return None
        password = prompt("Password: ")
        if not password:
            return None

        result = authenticate(username, password)
        if result:
            print(f"Welcome, {username}!")
            return username
        else:
            print("Invalid username or password.")
            retry = prompt("Try again? (yes/no): ")
            if retry.lower() != "yes":
                return None


def print_menu(is_admin_user):
    print("\n==== BaselFirewall CLI Menu ====")
    print("0. Exit")
    print("1. Add Allowed IP")
    print("2. Remove Allowed IP")
    print("3. Show Allowed IPs")
    print("4. Add Blocked Port")
    print("5. Remove Blocked Port")
    print("6. Show Blocked Ports")
    print("7. Enable Stateful Inspection")
    print("8. Disable Stateful Inspection")
    print("9. Enable IDS/IPS")
    print("10. Disable IDS/IPS")
    print("11. Enable NAT")
    print("12. Disable NAT")
    print("13. Set NAT IP")
    print("14. Enable DoS Protection")
    print("15. Disable DoS Protection")
    print("16. View Logs")
    print("17. View Alerts")
    if is_admin_user:
        print("18. Add User")
        print("19. Remove User")
        print("20. List Users")
        print("21. Reset Firewall Configuration")
        print("22. List Templates")
        print("23. Apply Template")
        print("24. Add Template")
        print("25. Delete Template")
        print("26. Logout")
        print("27. Clear Logs")


def add_allowed_ip_cli():
    ip = prompt("Enter IP to allow: ")
    if ip:
        allow_ip(ip)
        add_alert(f"Allowed IP added: {ip}", "INFO")
        log_event(f"Allowed IP added: {ip}", "INFO")
        print(f"Allowed IP {ip} added.")


def remove_allowed_ip_cli():
    ip = prompt("Enter IP to remove: ")
    if ip:
        confirm = prompt(f"Confirm remove allowed IP {ip}? (yes/no): ")
        if confirm.lower() == "yes":
            remove_allowed_ip(ip)
            add_alert(f"Allowed IP removed: {ip}", "WARNING")
            log_event(f"Allowed IP removed: {ip}", "WARNING")
            print(f"Allowed IP {ip} removed.")


def show_allowed_ips_cli():
    config = load_config()
    ips = config.get("allowed_ips", [])
    if ips:
        print("Allowed IPs:")
        for ip in ips:
            print(f" - {ip}")
    else:
        print("No allowed IPs configured.")


def add_blocked_port_cli():
    try:
        port = int(prompt("Enter port to block: "))
    except ValueError:
        print("Invalid port number.")
        return
    block_port(port)
    add_alert(f"Blocked port added: {port}", "INFO")
    log_event(f"Blocked port added: {port}", "INFO")
    print(f"Blocked port {port} added.")


def remove_blocked_port_cli():
    try:
        port = int(prompt("Enter port to remove: "))
    except ValueError:
        print("Invalid port number.")
        return
    confirm = prompt(f"Confirm remove blocked port {port}? (yes/no): ")
    if confirm.lower() == "yes":
        remove_blocked_port(port)
        add_alert(f"Blocked port removed: {port}", "WARNING")
        log_event(f"Blocked port removed: {port}", "WARNING")
        print(f"Blocked port {port} removed.")


def show_blocked_ports_cli():
    config = load_config()
    ports = config.get("blocked_ports", [])
    if ports:
        print("Blocked Ports:")
        for port in ports:
            print(f" - {port}")
    else:
        print("No blocked ports configured.")


def enable_stateful_cli():
    enable_stateful_inspection()
    add_alert("Stateful Inspection enabled", "INFO")
    log_event("Stateful Inspection enabled", "INFO")
    print("Stateful Inspection enabled.")


def disable_stateful_cli():
    disable_stateful_inspection()
    add_alert("Stateful Inspection disabled", "WARNING")
    log_event("Stateful Inspection disabled", "WARNING")
    print("Stateful Inspection disabled.")


def enable_ids_ips_cli():
    enable_ids_ips()
    add_alert("IDS/IPS enabled", "INFO")
    log_event("IDS/IPS enabled", "INFO")
    print("IDS/IPS enabled.")


def disable_ids_ips_cli():
    disable_ids_ips()
    add_alert("IDS/IPS disabled", "WARNING")
    log_event("IDS/IPS disabled", "WARNING")
    print("IDS/IPS disabled.")


def enable_nat_cli():
    enable_nat()
    add_alert("NAT enabled", "INFO")
    log_event("NAT enabled", "INFO")
    print("NAT enabled.")


def disable_nat_cli():
    disable_nat()
    add_alert("NAT disabled", "WARNING")
    log_event("NAT disabled", "WARNING")
    print("NAT disabled.")


def set_nat_ip_cli():
    nat_ip = prompt("Enter NAT IP: ")
    if nat_ip:
        set_nat_config(nat_ip)
        add_alert(f"NAT IP configured: {nat_ip}", "INFO")
        log_event(f"NAT IP configured: {nat_ip}", "INFO")
        print(f"NAT IP set to {nat_ip}.")


def enable_dos_cli():
    enable_dos_protection()
    add_alert("DoS Protection enabled", "INFO")
    log_event("DoS Protection enabled", "INFO")
    print("DoS Protection enabled.")


def disable_dos_cli():
    disable_dos_protection()
    add_alert("DoS Protection disabled", "WARNING")
    log_event("DoS Protection disabled", "WARNING")
    print("DoS Protection disabled.")


def view_logs_cli():
    """Display logs with color coding and formatting"""
    init()

    logs = view_logs()
    sections = logs.split("\n\n=== ")

    print("\n=== Firewall Logs ===")
    for line in sections[0].splitlines():
        if "ERROR" in line or "CRITICAL" in line:
            print(f"{Fore.RED}{line}{Style.RESET_ALL}")
        elif "WARNING" in line:
            print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")

    if len(sections) > 1:
        print("\n=== Connection Logs ===")
        for line in sections[1].splitlines():
            if "BLOCKED" in line:
                print(f"{Fore.RED}{line}{Style.RESET_ALL}")
            elif "NEW" in line:
                print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            else:
                print(line)

    if len(sections) > 2:
        print("\n=== IPTables Logs ===")
        for line in sections[2].splitlines():
            if "DROP" in line:
                print(f"{Fore.RED}{line}{Style.RESET_ALL}")
            elif "NEW_CONNECTION" in line:
                print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            elif "STEALTH_SCAN" in line or "XMAS_SCAN" in line:
                print(f"{Fore.MAGENTA}{line}{Style.RESET_ALL}")
            else:
                print(line)


def clear_logs_cli():
    confirm = prompt("Are you sure you want to clear all logs? (yes/no): ")
    if confirm.lower() == "yes":
        result = clear_logs()
        add_alert("Firewall logs cleared via CLI", "WARNING")
        log_event("Firewall logs cleared via CLI", "WARNING")
        print(result)
    else:
        print("Clear logs cancelled.")


def view_alerts_cli():
    """Display alerts with color coding"""
    init()

    alerts = get_live_alerts()
    print("\n=== Live Alerts ===")
    if alerts:
        for alert in alerts:
            if "ERROR" in alert or "CRITICAL" in alert:
                print(f"{Fore.RED}❌ {alert}{Style.RESET_ALL}")
            elif "WARNING" in alert:
                print(f"{Fore.YELLOW}⚠️ {alert}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}ℹ️ {alert}{Style.RESET_ALL}")
    else:
        print("No alerts.")


def add_user_cli():
    username = prompt("New username: ")
    password = prompt("New password: ")
    role = prompt("Role (admin/user): ").lower()
    if role not in ["admin", "user"]:
        print("Invalid role. Must be 'admin' or 'user'.")
        return
    try:
        add_user(username, password, role)
        add_alert(f"User added: {username} (Role: {role})", "INFO")
        log_event(f"User added: {username} (Role: {role})", "INFO")
        print(f"User {username} added.")
    except Exception as e:
        print(f"Error adding user: {e}")


def remove_user_cli():
    username = prompt("Username to remove: ")
    confirm = prompt(f"Confirm remove user {username}? (yes/no): ")
    if confirm.lower() == "yes":
        try:
            remove_user(username)
            add_alert(f"User removed: {username}", "WARNING")
            log_event(f"User removed: {username}", "WARNING")
            print(f"User {username} removed.")
        except Exception as e:
            print(f"Error removing user: {e}")


def list_users_cli():
    users = list_users()
    if users:
        print("Users:")
        for u in users:
            print(f" - {u['username']} ({u['role']})")
    else:
        print("No users found.")


def reset_firewall_cli():
    confirm = prompt("Confirm reset firewall configuration? (yes/no): ")
    if confirm.lower() == "yes":
        reset_config()
        add_alert("Firewall configuration reset", "WARNING")
        log_event("Firewall configuration reset", "WARNING")
        print("Firewall configuration reset.")


def main():
    username = login()
    if not username:
        return

    is_admin_user = is_admin(username)
    while True:
        print_menu(is_admin_user)
        choice = prompt("\nEnter your choice: ")

        if choice == "0":
            print("Exiting...")
            break
        elif choice == "1":
            add_allowed_ip_cli()
        elif choice == "2":
            remove_allowed_ip_cli()
        elif choice == "3":
            show_allowed_ips_cli()
        elif choice == "4":
            add_blocked_port_cli()
        elif choice == "5":
            remove_blocked_port_cli()
        elif choice == "6":
            show_blocked_ports_cli()
        elif choice == "7":
            enable_stateful_cli()
        elif choice == "8":
            disable_stateful_cli()
        elif choice == "9":
            enable_ids_ips_cli()
        elif choice == "10":
            disable_ids_ips_cli()
        elif choice == "11":
            enable_nat_cli()
        elif choice == "12":
            disable_nat_cli()
        elif choice == "13":
            set_nat_ip_cli()
        elif choice == "14":
            enable_dos_cli()
        elif choice == "15":
            disable_dos_cli()
        elif choice == "16":
            view_logs_cli()
        elif choice == "17":
            view_alerts_cli()
        elif is_admin_user and choice == "18":
            add_user_cli()
        elif is_admin_user and choice == "19":
            remove_user_cli()
        elif is_admin_user and choice == "20":
            list_users_cli()
        elif is_admin_user and choice == "21":
            reset_firewall_cli()
        elif is_admin_user and choice == "22":
            list_templates_cli()
        elif is_admin_user and choice == "23":
            apply_template_cli()
        elif is_admin_user and choice == "24":
            add_template_cli()
        elif is_admin_user and choice == "25":
            delete_template_cli()
        elif is_admin_user and choice == "26":
            print("Logging out...")
            break
        elif is_admin_user and choice == "27":
            clear_logs_cli()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
