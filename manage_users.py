import os
import json
import bcrypt
from firewall.logging import log_event
from firewall.alerts import add_alert
import sys
import getpass

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "firewall")))
from auth import load_users, save_users, hash_password

USER_DB_FILE = os.path.join(os.path.dirname(__file__), "config/users.json")


def delete_user(username):
    users = load_users()
    if username in users:
        confirm = (
            input(f"Are you sure you want to delete user '{username}'? (y/n): ")
            .strip()
            .lower()
        )
        if confirm == "y":
            del users[username]
            save_users(users)
            print(f"[+] User '{username}' has been deleted.")
        else:
            print("[!] Operation canceled.")
    else:
        print("[-] User not found.")


def reset_password(username):
    users = load_users()
    if username in users:
        password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        if password != confirm_password:
            print("[-] Passwords do not match.")
            return
        users[username]["password"] = hash_password(password)
        save_users(users)
        print(f"[+] Password for user '{username}' has been reset.")
    else:
        print("[-] User not found.")


def menu():
    while True:
        print("\n=== Basel Firewall User Management ===")
        print("1. Delete User")
        print("2. Reset User Password")
        print("0. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            username = input("Enter username to delete: ").strip()
            delete_user(username)
        elif choice == "2":
            username = input("Enter username to reset password: ").strip()
            reset_password(username)
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    menu()
