import sys 
from firewall.auth import authenticate, is_admin, add_user, remove_user, list_users, log_login_attempt
from firewall.rules import allow_ip, remove_allowed_ip, block_port, remove_blocked_port
from firewall.config_manager import load_config, reset_config, set_nat_config
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.nat import enable_nat, disable_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.logging import log_event, view_logs, clear_logs
from firewall.alerts import add_alert, get_live_alerts

def prompt(msg):
    return input(msg).strip()

def login():
    print("==== BaselFirewall CLI Login ====")
    username = prompt("Username: ")
    password = prompt("Password: ")
    if authenticate(username, password):
        log_login_attempt(username, True)
        add_alert(f"User '{username}' logged in via CLI", "INFO")
        log_event(f"User '{username}' logged in via CLI", "INFO")
        print(f"Welcome, {username}!")
        return username
    else:
        log_login_attempt(username, False)
        print("Invalid username or password.")
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
        print("22. Logout")
        print("23. Clear Logs")

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
    logs = view_logs()
    print("---- Firewall Logs ----")
    print(logs)

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
    alerts = get_live_alerts()
    print("---- Live Alerts ----")
    if alerts:
        for alert in alerts:
            print(f" - {alert}")
    else:
        print("No alerts.")

def add_user_cli():
    username = prompt("New username: ")
    password = prompt("New password: ")
    role = prompt("Role (admin/user): ").lower()
    if role not in ['admin', 'user']:
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
    username = None
    while not username:
        username = login()
    admin = is_admin(username)

    while True:
        print_menu(admin)
        choice = prompt("Enter choice: ")
        if not choice.isdigit():
            print("Invalid input, enter a number.")
            continue
        choice = int(choice)

        if choice == 0:
            add_alert(f"User '{username}' logged out", "INFO")
            log_event(f"User '{username}' logged out", "INFO")
            print("Exiting BaselFirewall CLI. Goodbye!")
            sys.exit(0)

        elif choice == 1:
            add_allowed_ip_cli()
        elif choice == 2:
            remove_allowed_ip_cli()
        elif choice == 3:
            show_allowed_ips_cli()
        elif choice == 4:
            add_blocked_port_cli()
        elif choice == 5:
            remove_blocked_port_cli()
        elif choice == 6:
            show_blocked_ports_cli()
        elif choice == 7:
            enable_stateful_cli()
        elif choice == 8:
            disable_stateful_cli()
        elif choice == 9:
            enable_ids_ips_cli()
        elif choice == 10:
            disable_ids_ips_cli()
        elif choice == 11:
            enable_nat_cli()
        elif choice == 12:
            disable_nat_cli()
        elif choice == 13:
            set_nat_ip_cli()
        elif choice == 14:
            enable_dos_cli()
        elif choice == 15:
            disable_dos_cli()
        elif choice == 16:
            view_logs_cli()
        elif choice == 17:
            view_alerts_cli()
        elif choice == 18 and admin:
            add_user_cli()
        elif choice == 19 and admin:
            remove_user_cli()
        elif choice == 20 and admin:
            list_users_cli()
        elif choice == 21 and admin:
            reset_firewall_cli()
        elif choice == 22 and admin:
            add_alert(f"User '{username}' logged out", "INFO")
            log_event(f"User '{username}' logged out", "INFO")
            print("Logging out...")
            username = None
            while not username:
                username = login()
            admin = is_admin(username)
        elif choice == 23 and admin:
            clear_logs_cli()
        else:
            print("Invalid choice or insufficient privileges.")

if __name__ == "__main__":
    main()
