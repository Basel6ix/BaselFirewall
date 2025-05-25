import sys

def launch_cli():
    from cli.cli import main
    main()

def launch_gui():
    from gui.interface import BaselFirewallGUI
    BaselFirewallGUI()

def main():
    while True:
        print("\n=== Basel Firewall Launcher ===")
        print("1. Launch CLI")
        print("2. Launch GUI")
        print("0. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            launch_cli()
        elif choice == "2":
            launch_gui()
        elif choice == "0":
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter 0, 1, or 2.")

if __name__ == "__main__":
    main()
