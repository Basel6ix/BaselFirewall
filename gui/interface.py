import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from firewall.auth import authenticate, is_admin, add_user, remove_user, list_users, log_login_attempt
from firewall.rules import allow_ip, remove_allowed_ip, block_port, remove_blocked_port
from firewall.config_manager import load_config, reset_config, set_nat_config
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.nat import enable_nat, disable_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.logging import log_event, view_logs, clear_logs
from firewall.alerts import add_alert, get_live_alerts

class LoginDialog(simpledialog.Dialog):
    def body(self, master):
        self.title("BaselFirewall Login")
        ttk.Label(master, text="Username:").grid(row=0, sticky=tk.W)
        ttk.Label(master, text="Password:").grid(row=1, sticky=tk.W)
        self.username_entry = ttk.Entry(master)
        self.password_entry = ttk.Entry(master, show="*")
        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)
        return self.username_entry

    def apply(self):
        self.username = self.username_entry.get().strip()
        self.password = self.password_entry.get().strip()

class BaselFirewallGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BaselFirewall GUI")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.username = None
        self.admin = False

        self.login()

    def login(self):
        while True:
            dlg = LoginDialog(self)
            username = getattr(dlg, "username", None)
            password = getattr(dlg, "password", None)
            if not username or not password:
                self.destroy()
                return
            if authenticate(username, password):
                log_login_attempt(username, True)
                add_alert(f"User '{username}' logged in via GUI", "INFO")
                log_event(f"User '{username}' logged in via GUI", "INFO")
                self.username = username
                self.admin = is_admin(username)
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                break
            else:
                log_login_attempt(username, False)
                messagebox.showerror("Login Failed", "Invalid username or password.")

        self.build_interface()

    def build_interface(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        self.create_firewall_rules_tab()
        self.create_features_tab()
        self.create_logs_tab()
        if self.admin:
            self.create_user_management_tab()
            self.create_configuration_tab()

        self.create_logout_button()

    def create_firewall_rules_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Firewall Rules")

        allowed_frame = ttk.LabelFrame(tab, text="Allowed IPs")
        allowed_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.allowed_ips_listbox = tk.Listbox(allowed_frame, height=8)
        self.allowed_ips_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5), pady=5)

        allowed_buttons = ttk.Frame(allowed_frame)
        allowed_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(allowed_buttons, text="Add Allowed IP", command=self.add_allowed_ip_gui).pack(fill=tk.X, pady=2)
        ttk.Button(allowed_buttons, text="Remove Selected IP", command=self.remove_allowed_ip_gui).pack(fill=tk.X, pady=2)
        ttk.Button(allowed_buttons, text="Refresh List", command=self.load_allowed_ips).pack(fill=tk.X, pady=2)

        blocked_frame = ttk.LabelFrame(tab, text="Blocked Ports")
        blocked_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.blocked_ports_listbox = tk.Listbox(blocked_frame, height=8)
        self.blocked_ports_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5), pady=5)

        blocked_buttons = ttk.Frame(blocked_frame)
        blocked_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(blocked_buttons, text="Add Blocked Port", command=self.add_blocked_port_gui).pack(fill=tk.X, pady=2)
        ttk.Button(blocked_buttons, text="Remove Selected Port", command=self.remove_blocked_port_gui).pack(fill=tk.X, pady=2)
        ttk.Button(blocked_buttons, text="Refresh List", command=self.load_blocked_ports).pack(fill=tk.X, pady=2)

        self.load_allowed_ips()
        self.load_blocked_ports()

    def load_allowed_ips(self):
        self.allowed_ips_listbox.delete(0, tk.END)
        config = load_config()
        for ip in config.get("allowed_ips", []):
            self.allowed_ips_listbox.insert(tk.END, ip)

    def add_allowed_ip_gui(self):
        ip = simpledialog.askstring("Add Allowed IP", "Enter IP to allow:")
        if ip:
            allow_ip(ip)
            add_alert(f"Allowed IP added: {ip}", "INFO")
            log_event(f"Allowed IP added: {ip}", "INFO")
            messagebox.showinfo("Success", f"Allowed IP {ip} added.")
            self.load_allowed_ips()

    def remove_allowed_ip_gui(self):
        selection = self.allowed_ips_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No allowed IP selected.")
            return
        ip = self.allowed_ips_listbox.get(selection[0])
        if messagebox.askyesno("Confirm", f"Remove allowed IP {ip}?"):
            remove_allowed_ip(ip)
            add_alert(f"Allowed IP removed: {ip}", "WARNING")
            log_event(f"Allowed IP removed: {ip}", "WARNING")
            messagebox.showinfo("Success", f"Allowed IP {ip} removed.")
            self.load_allowed_ips()

    def load_blocked_ports(self):
        self.blocked_ports_listbox.delete(0, tk.END)
        config = load_config()
        for port in config.get("blocked_ports", []):
            self.blocked_ports_listbox.insert(tk.END, str(port))

    def add_blocked_port_gui(self):
        port_str = simpledialog.askstring("Add Blocked Port", "Enter port to block:")
        if port_str:
            try:
                port = int(port_str)
                block_port(port)
                add_alert(f"Blocked port added: {port}", "INFO")
                log_event(f"Blocked port added: {port}", "INFO")
                messagebox.showinfo("Success", f"Blocked port {port} added.")
                self.load_blocked_ports()
            except ValueError:
                messagebox.showerror("Invalid Input", "Port must be a number.")

    def remove_blocked_port_gui(self):
        selection = self.blocked_ports_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No blocked port selected.")
            return
        port_str = self.blocked_ports_listbox.get(selection[0])
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Selected port invalid.")
            return
        if messagebox.askyesno("Confirm", f"Remove blocked port {port}?"):
            remove_blocked_port(port)
            add_alert(f"Blocked port removed: {port}", "WARNING")
            log_event(f"Blocked port removed: {port}", "WARNING")
            messagebox.showinfo("Success", f"Blocked port {port} removed.")
            self.load_blocked_ports()

    def create_features_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Features")

        self.stateful_var = tk.BooleanVar()
        stateful_frame = ttk.LabelFrame(tab, text="Stateful Inspection")
        stateful_frame.pack(fill=tk.X, padx=10, pady=5)
        self.stateful_check = ttk.Checkbutton(stateful_frame, text="Enable Stateful Inspection",
                                              variable=self.stateful_var, command=self.toggle_stateful)
        self.stateful_check.pack(anchor=tk.W, padx=5, pady=5)

        self.ids_ips_var = tk.BooleanVar()
        ids_ips_frame = ttk.LabelFrame(tab, text="IDS/IPS")
        ids_ips_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ids_ips_check = ttk.Checkbutton(ids_ips_frame, text="Enable IDS/IPS",
                                             variable=self.ids_ips_var, command=self.toggle_ids_ips)
        self.ids_ips_check.pack(anchor=tk.W, padx=5, pady=5)

        self.nat_var = tk.BooleanVar()
        nat_frame = ttk.LabelFrame(tab, text="NAT")
        nat_frame.pack(fill=tk.X, padx=10, pady=5)
        self.nat_check = ttk.Checkbutton(nat_frame, text="Enable NAT",
                                         variable=self.nat_var, command=self.toggle_nat)
        self.nat_check.pack(anchor=tk.W, padx=5, pady=5)

        ttk.Button(nat_frame, text="Set NAT IP", command=self.set_nat_ip_gui).pack(padx=5, pady=5)

        self.dos_var = tk.BooleanVar()
        dos_frame = ttk.LabelFrame(tab, text="DoS Protection")
        dos_frame.pack(fill=tk.X, padx=10, pady=5)
        self.dos_check = ttk.Checkbutton(dos_frame, text="Enable DoS Protection",
                                         variable=self.dos_var, command=self.toggle_dos)
        self.dos_check.pack(anchor=tk.W, padx=5, pady=5)

        self.load_feature_states()

    def load_feature_states(self):
        config = load_config()
        self.stateful_var.set(config.get("stateful_inspection", False))
        self.ids_ips_var.set(config.get("ids_ips", False))
        self.nat_var.set(config.get("nat_enabled", False))
        self.dos_var.set(config.get("dos_protection", False))

    def toggle_stateful(self):
        if self.stateful_var.get():
            enable_stateful_inspection()
            add_alert("Stateful Inspection enabled", "INFO")
            log_event("Stateful Inspection enabled", "INFO")
            messagebox.showinfo("Stateful Inspection", "Stateful Inspection enabled.")
        else:
            disable_stateful_inspection()
            add_alert("Stateful Inspection disabled", "WARNING")
            log_event("Stateful Inspection disabled", "WARNING")
            messagebox.showinfo("Stateful Inspection", "Stateful Inspection disabled.")

    def toggle_ids_ips(self):
        if self.ids_ips_var.get():
            enable_ids_ips()
            add_alert("IDS/IPS enabled", "INFO")
            log_event("IDS/IPS enabled", "INFO")
            messagebox.showinfo("IDS/IPS", "IDS/IPS enabled.")
        else:
            disable_ids_ips()
            add_alert("IDS/IPS disabled", "WARNING")
            log_event("IDS/IPS disabled", "WARNING")
            messagebox.showinfo("IDS/IPS", "IDS/IPS disabled.")

    def toggle_nat(self):
        if self.nat_var.get():
            enable_nat()
            add_alert("NAT enabled", "INFO")
            log_event("NAT enabled", "INFO")
            messagebox.showinfo("NAT", "NAT enabled.")
        else:
            disable_nat()
            add_alert("NAT disabled", "WARNING")
            log_event("NAT disabled", "WARNING")
            messagebox.showinfo("NAT", "NAT disabled.")

    def set_nat_ip_gui(self):
        ip = simpledialog.askstring("Set NAT IP", "Enter NAT IP address:")
        if ip:
            set_nat_config(ip)
            add_alert(f"NAT IP set to {ip}", "INFO")
            log_event(f"NAT IP set to {ip}", "INFO")
            messagebox.showinfo("NAT IP", f"NAT IP set to {ip}")

    def toggle_dos(self):
        if self.dos_var.get():
            enable_dos_protection()
            add_alert("DoS Protection enabled", "INFO")
            log_event("DoS Protection enabled", "INFO")
            messagebox.showinfo("DoS Protection", "DoS Protection enabled.")
        else:
            disable_dos_protection()
            add_alert("DoS Protection disabled", "WARNING")
            log_event("DoS Protection disabled", "WARNING")
            messagebox.showinfo("DoS Protection", "DoS Protection disabled.")

    def create_logs_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Logs & Alerts")

        logs_frame = ttk.LabelFrame(tab, text="Firewall Logs")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.logs_text = tk.Text(logs_frame, height=12, state=tk.DISABLED)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Button(logs_frame, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(logs_frame, text="Clear Logs", command=self.clear_logs_gui).pack(side=tk.LEFT, padx=5, pady=5)

        alerts_frame = ttk.LabelFrame(tab, text="Live Alerts")
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.alerts_text = tk.Text(alerts_frame, height=8, state=tk.DISABLED, foreground="red")
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Button(alerts_frame, text="Refresh Alerts", command=self.refresh_alerts).pack(padx=5, pady=5)

        self.refresh_logs()
        self.refresh_alerts()

    def refresh_logs(self):
        logs = view_logs()
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.insert(tk.END, logs)
        self.logs_text.config(state=tk.DISABLED)

    def clear_logs_gui(self):
        if messagebox.askyesno("Confirm Clear Logs", "Are you sure you want to clear all logs?"):
            clear_logs()
            add_alert(f"User '{self.username}' cleared logs.", "WARNING")
            log_event(f"User '{self.username}' cleared logs.", "WARNING")
            self.refresh_logs()
            messagebox.showinfo("Logs Cleared", "All logs have been cleared.")

    def refresh_alerts(self):
        alerts = get_live_alerts()
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        for alert in alerts:
            self.alerts_text.insert(tk.END, f"{alert}\n")
        self.alerts_text.config(state=tk.DISABLED)

    def create_user_management_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="User Management (Admin)")

        user_frame = ttk.LabelFrame(tab, text="Users")
        user_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.users_listbox = tk.Listbox(user_frame, height=10)
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,5), pady=5)

        user_buttons = ttk.Frame(user_frame)
        user_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(user_buttons, text="Add User", command=self.add_user_gui).pack(fill=tk.X, pady=2)
        ttk.Button(user_buttons, text="Remove Selected User", command=self.remove_user_gui).pack(fill=tk.X, pady=2)
        ttk.Button(user_buttons, text="Refresh User List", command=self.load_users).pack(fill=tk.X, pady=2)

        self.load_users()

    def load_users(self):
        self.users_listbox.delete(0, tk.END)
        users = list_users()
        for user in users:
            self.users_listbox.insert(tk.END, user)

    def add_user_gui(self):
        username = simpledialog.askstring("Add User", "Enter new username:")
        if not username:
            return
        password = simpledialog.askstring("Add User", f"Enter password for {username}:", show="*")
        if not password:
            return
        role = simpledialog.askstring("Add User", "Enter role (admin/user):").lower()
        if role not in ("admin", "user"):
            messagebox.showerror("Invalid Role", "Role must be 'admin' or 'user'.")
            return
        if add_user(username, password, role):
            add_alert(f"Admin '{self.username}' added user '{username}' with role '{role}'", "INFO")
            log_event(f"Admin '{self.username}' added user '{username}' with role '{role}'", "INFO")
            messagebox.showinfo("Success", f"User '{username}' added.")
            self.load_users()
        else:
            messagebox.showerror("Error", "Failed to add user. User may already exist.")

    def remove_user_gui(self):
        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No user selected.")
            return
        user = self.users_listbox.get(selection[0])
        if user == self.username:
            messagebox.showwarning("Action Denied", "You cannot remove yourself.")
            return
        if messagebox.askyesno("Confirm", f"Remove user '{user}'?"):
            if remove_user(user):
                add_alert(f"Admin '{self.username}' removed user '{user}'", "WARNING")
                log_event(f"Admin '{self.username}' removed user '{user}'", "WARNING")
                messagebox.showinfo("Success", f"User '{user}' removed.")
                self.load_users()
            else:
                messagebox.showerror("Error", "Failed to remove user.")

    def create_configuration_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Configuration (Admin)")

        config_frame = ttk.Frame(tab)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Button(config_frame, text="Reset Firewall Configuration", command=self.reset_config_gui).pack(pady=10)
        ttk.Button(config_frame, text="Clear Firewall Logs", command=self.clear_logs_gui).pack(pady=10)

    def reset_config_gui(self):
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset the firewall configuration? This action cannot be undone."):
            reset_config()
            add_alert(f"Admin '{self.username}' reset firewall configuration", "WARNING")
            log_event(f"Admin '{self.username}' reset firewall configuration", "WARNING")
            messagebox.showinfo("Reset Complete", "Firewall configuration has been reset.")
            self.load_allowed_ips()
            self.load_blocked_ports()
            self.load_feature_states()

    def create_logout_button(self):
        btn = ttk.Button(self, text="Logout", command=self.logout)
        btn.pack(side=tk.BOTTOM, pady=5)

    def logout(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            add_alert(f"User '{self.username}' logged out via GUI", "INFO")
            log_event(f"User '{self.username}' logged out via GUI", "INFO")
            self.destroy()
            self.__init__()

    def on_close(self):
        if messagebox.askyesno("Exit BaselFirewall", "Are you sure you want to exit?"):
            if self.username:
                add_alert(f"User '{self.username}' exited BaselFirewall GUI", "INFO")
                log_event(f"User '{self.username}' exited BaselFirewall GUI", "INFO")
            self.destroy()


if __name__ == "__main__":
    app = BaselFirewallGUI()
    app.mainloop()
