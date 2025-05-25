import sys
import os
import getpass

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from firewall.auth import register_user

def main():
    print("👤 User Registration for Basel Firewall")

    username = input("Enter new username: ").strip()
    password = getpass.getpass("Enter password: ").strip()
    confirm = getpass.getpass("Confirm password: ").strip()

    if password != confirm:
        print("❌ Passwords do not match.")
        return

    role = input("Role (admin/user) [default=user]: ").strip().lower()
    if role not in ["admin", "user", ""]:
        print("❌ Invalid role. Use 'admin' or 'user'.")
        return

    if role == "":
        role = "user"

    success, message = register_user(username, password, role)
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ {message}")

if __name__ == "__main__":
    main()
