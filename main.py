import sys
import argparse
from firewall.rules import disable_firewall, enable_firewall
from firewall.config_manager import load_config

def launch_cli():
    from cli.cli import main
    main()

def launch_gui():
    from gui.interface import BaselFirewallGUI
    BaselFirewallGUI()

def toggle_firewall():
    config = load_config()
    if config.get("firewall_enabled", True):
        if disable_firewall():
            print("Firewall has been completely disabled.")
        else:
            print("Failed to disable firewall. Check logs for details.")
    else:
        if enable_firewall():
            print("Firewall has been re-enabled with default configuration.")
        else:
            print("Failed to enable firewall. Check logs for details.")

def run_daemon():
    # Enable firewall by default in daemon mode
    if not load_config().get("firewall_enabled", True):
        enable_firewall()
    
    # Keep the process running
    while True:
        try:
            import time
            time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            break

def main():
    parser = argparse.ArgumentParser(description='BaselFirewall')
    parser.add_argument('--daemon', action='store_true', help='Run in daemon mode')
    args = parser.parse_args()

    if args.daemon:
        run_daemon()
        return

    while True:
        config = load_config()
        firewall_status = "ENABLED" if config.get("firewall_enabled", True) else "DISABLED"
        
        print("\n=== Basel Firewall Launcher ===")
        print(f"Firewall Status: {firewall_status}")
        print("1. Launch CLI")
        print("2. Launch GUI")
        print("3. Toggle Firewall (Enable/Disable)")
        print("0. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            launch_cli()
        elif choice == "2":
            launch_gui()
        elif choice == "3":
            toggle_firewall()
        elif choice == "0":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter 0, 1, 2, or 3.")

if __name__ == "__main__":
    main()
