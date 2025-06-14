#!/usr/bin/env python3

import sys
import os
import argparse
from firewall.rules import enable_firewall, disable_firewall
from firewall.config_manager import load_config, save_config
from firewall.logging import log_event
from cli.cli import main as cli_main
from gui.interface import main as gui_main

def get_firewall_status():
    """Get detailed firewall status"""
    try:
        config = load_config()
        status = {
            "enabled": config.get("firewall_enabled", True),
            "dos_protection": config.get("dos_protection_enabled", False),
            "ids_ips": config.get("ids_ips_enabled", False),
            "stateful": config.get("stateful_enabled", True),
            "nat": config.get("nat_enabled", False)
        }
        return status
    except Exception as e:
        log_event(f"Error getting firewall status: {str(e)}", "ERROR")
        return None

def toggle_firewall():
    """Toggle firewall state between enabled and disabled"""
    try:
        config = load_config()
        current_state = config.get("firewall_enabled", True)
        
        if current_state:
            # Currently enabled, so disable it
            if disable_firewall():
                config["firewall_enabled"] = False
                if save_config(config):
                    print("Firewall has been disabled.")
                    log_event("Firewall disabled via toggle", "WARNING")
                    return True
                else:
                    print("Failed to save firewall state.")
                    return False
            else:
                print("Failed to disable firewall.")
                return False
        else:
            # Currently disabled, so enable it
            if enable_firewall():
                config["firewall_enabled"] = True
                if save_config(config):
                    print("Firewall has been enabled with default configuration.")
                    log_event("Firewall enabled via toggle", "INFO")
                    return True
                else:
                    print("Failed to save firewall state.")
                    return False
            else:
                print("Failed to enable firewall.")
                return False
    except Exception as e:
        log_event(f"Error toggling firewall: {str(e)}", "ERROR")
        print(f"Error toggling firewall: {e}")
        return False

def print_status():
    """Print detailed firewall status"""
    status = get_firewall_status()
    if status is None:
        print("Error: Could not get firewall status")
        return False
    
    print("\nBaselFirewall Status:")
    print(f"Firewall: {'Enabled' if status['enabled'] else 'Disabled'}")
    print(f"DoS Protection: {'Enabled' if status['dos_protection'] else 'Disabled'}")
    print(f"IDS/IPS: {'Enabled' if status['ids_ips'] else 'Disabled'}")
    print(f"Stateful Inspection: {'Enabled' if status['stateful'] else 'Disabled'}")
    print(f"NAT: {'Enabled' if status['nat'] else 'Disabled'}")
    return True

def select_interface():
    """Prompt user to select interface mode"""
    while True:
        # Get current firewall status
        status = get_firewall_status()
        if status is None:
            print("\nError: Could not get firewall status")
            return None
            
        print("\nBaselFirewall Interface Selection")
        print("-" * 35)
        print(f"Current Status: {'ENABLED' if status['enabled'] else 'DISABLED'}")
        print("-" * 35)
        print("1. Command Line Interface (CLI)")
        print("2. Graphical User Interface (GUI)")
        print("3. Toggle Firewall (Enable/Disable)")
        print("4. Show Detailed Status")
        print("0. Exit")
        
        try:
            choice = input("\nSelect option (0-4): ").strip()
            if choice == "0":
                return None
            elif choice == "1":
                return "cli"
            elif choice == "2":
                return "gui"
            elif choice == "3":
                result = toggle_firewall()
                if result:
                    print("\nFirewall state toggled successfully.")
                else:
                    print("\nFailed to toggle firewall state.")
                input("\nPress Enter to continue...")
                continue
            elif choice == "4":
                print_status()
                input("\nPress Enter to continue...")
                continue
            else:
                print("\nInvalid choice. Please select 0-4.")
                continue
        except KeyboardInterrupt:
            return None
        except Exception as e:
            print(f"\nError: {str(e)}")
            print("Please try again.")
            continue

def main():
    parser = argparse.ArgumentParser(description='BaselFirewall - Advanced Firewall Protection System')
    parser.add_argument('-c', '--cli', action='store_true', help='Start CLI interface')
    parser.add_argument('-g', '--gui', action='store_true', help='Start GUI interface')
    parser.add_argument('-t', '--toggle', action='store_true', help='Toggle firewall state')
    parser.add_argument('-s', '--status', action='store_true', help='Show firewall status')
    parser.add_argument('-d', '--disable', action='store_true', help='Disable firewall')
    parser.add_argument('-e', '--enable', action='store_true', help='Enable firewall')

    args = parser.parse_args()

    try:
        # Handle command line arguments
        if args.status:
            return 0 if print_status() else 1

        if args.toggle:
            return 0 if toggle_firewall() else 1

        if args.disable:
            if disable_firewall():
                config = load_config()
                config["firewall_enabled"] = False
                if save_config(config):
                    print("Firewall disabled.")
                    return 0
                else:
                    print("Failed to save firewall state.")
                    return 1
            print("Failed to disable firewall.")
            return 1

        if args.enable:
            if enable_firewall():
                config = load_config()
                config["firewall_enabled"] = True
                if save_config(config):
                    print("Firewall enabled.")
                    return 0
                else:
                    print("Failed to save firewall state.")
                    return 1
            print("Failed to enable firewall.")
            return 1

        # If both GUI and CLI are specified, prefer GUI
        if args.gui:
            gui_main()
        elif args.cli:
            cli_main()
        else:
            # No interface specified, ask user to choose
            choice = select_interface()
            if choice == "gui":
                gui_main()
            elif choice == "cli":
                cli_main()
            else:
                print("Exiting...")
                return 0
        return 0

    except Exception as e:
        log_event(f"Critical error in main: {str(e)}", "CRITICAL")
        print(f"Critical error: {str(e)}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
