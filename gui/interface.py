import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, scrolledtext
import json
import os
import time
from firewall.config_manager import load_config, save_config, reset_config, set_nat_config
from firewall.rules import allow_ip, remove_allowed_ip, block_port, remove_blocked_port
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.nat import enable_nat, disable_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.logging import log_event, view_logs, clear_logs, show_iptables_logs
from firewall.alerts import add_alert, get_live_alerts
from firewall.auth import add_user, remove_user, list_users, is_admin, authenticate, log_login_attempt
from colorama import init, Fore, Style
import subprocess


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
        self.result = (self.username_entry.get().strip(), self.password_entry.get().strip())

    def validate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return False
        return True


class BaselFirewallGUI(tk.Tk):
    def __init__(self):
        """Initialize the GUI"""
        super().__init__()

        # Initialize variables
        self.username = None
        self.admin = False
        self.auto_refresh_alerts_id = None
        self.auto_refresh_logs_id = None
        self.quit_flag = False
        
        # Initialize auto-refresh variables
        self.firewall_auto_refresh = tk.BooleanVar(value=True)
        self.iptables_auto_refresh = tk.BooleanVar(value=True)
        self.alerts_auto_refresh = tk.BooleanVar(value=True)

        # Configure window
        self.title("Basel Firewall")
        self.geometry("800x600")
        self.minsize(800, 600)

        # Configure styles
        style = ttk.Style()
        style.configure("Accent.TButton", 
                       background="#007bff",
                       foreground="white",
                       padding=5)

        # Attempt login
        if not self.login():
            self.destroy()
            return

        # Build interface
        self.build_interface()
        
        # Start auto-refresh
        self.start_auto_refresh()

    def login(self):
        """Handle user login"""
        while True:
            dialog = LoginDialog(self)
            if not dialog.result:
                self.destroy()
                return False

            username, password = dialog.result
            if not username or not password:
                self.destroy()
                return False

            if authenticate(username, password):
                log_login_attempt(username, True)
                self.username = username
                self.admin = is_admin(username)
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                return True
            else:
                log_login_attempt(username, False)
                messagebox.showerror("Login Failed", "Invalid username or password.")

    def build_interface(self):
        """Build the main interface"""
        # Create notebook for tabs
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.create_firewall_rules_tab()
        self.create_features_tab()
        self.create_logs_tab()
        if self.admin:
            self.create_user_management_tab()
            self.create_configuration_tab()

        # Create logout button
        self.create_logout_button()

        # Log successful login
        log_event(f"User '{self.username}' logged in via GUI", "INFO")

        # Set up window close handler
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_firewall_rules_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Firewall Rules")

        allowed_frame = ttk.LabelFrame(tab, text="Allowed IPs")
        allowed_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.allowed_ips_listbox = tk.Listbox(allowed_frame, height=8)
        self.allowed_ips_listbox.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5), pady=5
        )

        allowed_buttons = ttk.Frame(allowed_frame)
        allowed_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(
            allowed_buttons, text="Add Allowed IP", command=self.add_allowed_ip_gui
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            allowed_buttons,
            text="Remove Selected IP",
            command=self.remove_allowed_ip_gui,
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            allowed_buttons, text="Refresh List", command=self.load_allowed_ips
        ).pack(fill=tk.X, pady=2)

        blocked_frame = ttk.LabelFrame(tab, text="Blocked Ports")
        blocked_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.blocked_ports_listbox = tk.Listbox(blocked_frame, height=8)
        self.blocked_ports_listbox.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5), pady=5
        )

        blocked_buttons = ttk.Frame(blocked_frame)
        blocked_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(
            blocked_buttons, text="Add Blocked Port", command=self.add_blocked_port_gui
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            blocked_buttons,
            text="Remove Selected Port",
            command=self.remove_blocked_port_gui,
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            blocked_buttons, text="Refresh List", command=self.load_blocked_ports
        ).pack(fill=tk.X, pady=2)

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
        self.stateful_check = ttk.Checkbutton(
            stateful_frame,
            text="Enable Stateful Inspection",
            variable=self.stateful_var,
            command=self.toggle_stateful,
        )
        self.stateful_check.pack(anchor=tk.W, padx=5, pady=5)

        self.ids_ips_var = tk.BooleanVar()
        ids_ips_frame = ttk.LabelFrame(tab, text="IDS/IPS")
        ids_ips_frame.pack(fill=tk.X, padx=10, pady=5)
        self.ids_ips_check = ttk.Checkbutton(
            ids_ips_frame,
            text="Enable IDS/IPS",
            variable=self.ids_ips_var,
            command=self.toggle_ids_ips,
        )
        self.ids_ips_check.pack(anchor=tk.W, padx=5, pady=5)

        self.nat_var = tk.BooleanVar()
        nat_frame = ttk.LabelFrame(tab, text="NAT")
        nat_frame.pack(fill=tk.X, padx=10, pady=5)
        self.nat_check = ttk.Checkbutton(
            nat_frame, text="Enable NAT", variable=self.nat_var, command=self.toggle_nat
        )
        self.nat_check.pack(anchor=tk.W, padx=5, pady=5)

        ttk.Button(nat_frame, text="Set NAT IP", command=self.set_nat_ip_gui).pack(
            padx=5, pady=5
        )

        self.dos_var = tk.BooleanVar()
        dos_frame = ttk.LabelFrame(tab, text="DoS Protection")
        dos_frame.pack(fill=tk.X, padx=10, pady=5)
        self.dos_check = ttk.Checkbutton(
            dos_frame,
            text="Enable DoS Protection",
            variable=self.dos_var,
            command=self.toggle_dos,
        )
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
        """Create the logs tab"""
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Logs & Alerts")

        # Create notebook for log tabs
        log_notebook = ttk.Notebook(tab)
        log_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Firewall Logs Tab
        firewall_tab = ttk.Frame(log_notebook)
        log_notebook.add(firewall_tab, text="Firewall Logs")
        
        # Control frame for firewall logs
        firewall_control_frame = ttk.Frame(firewall_tab)
        firewall_control_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Checkbutton(
            firewall_control_frame,
            text="Auto Refresh",
            variable=self.firewall_auto_refresh
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            firewall_control_frame,
            text="Refresh Now",
            command=self.refresh_logs
        ).pack(side=tk.LEFT, padx=5)

        self.firewall_log_text = scrolledtext.ScrolledText(firewall_tab, height=20)
        self.firewall_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.firewall_log_text.tag_configure("INFO", foreground="black")
        self.firewall_log_text.tag_configure("WARNING", foreground="orange")
        self.firewall_log_text.tag_configure("ERROR", foreground="red")
        self.firewall_log_text.tag_configure("CRITICAL", foreground="red", font=("TkDefaultFont", 10, "bold"))

        # IPTables Logs Tab
        iptables_tab = ttk.Frame(log_notebook)
        log_notebook.add(iptables_tab, text="IPTables Logs")
        
        # Control frame for iptables logs
        iptables_control_frame = ttk.Frame(iptables_tab)
        iptables_control_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Checkbutton(
            iptables_control_frame,
            text="Auto Refresh",
            variable=self.iptables_auto_refresh
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            iptables_control_frame,
            text="Refresh Now",
            command=self.refresh_iptables
        ).pack(side=tk.LEFT, padx=5)

        self.iptables_text = scrolledtext.ScrolledText(iptables_tab, height=20)
        self.iptables_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.iptables_text.tag_configure("DROP", foreground="red")
        self.iptables_text.tag_configure("ACCEPT", foreground="green")
        self.iptables_text.tag_configure("NEW", foreground="blue")

        # Live Alerts Tab
        alerts_tab = ttk.Frame(log_notebook)
        log_notebook.add(alerts_tab, text="Live Alerts")
        
        # Control frame for alerts
        alerts_control_frame = ttk.Frame(alerts_tab)
        alerts_control_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Checkbutton(
            alerts_control_frame,
            text="Auto Refresh",
            variable=self.alerts_auto_refresh
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            alerts_control_frame,
            text="Refresh Now",
            command=self.refresh_alerts
        ).pack(side=tk.LEFT, padx=5)

        self.alerts_text = scrolledtext.ScrolledText(alerts_tab, height=20)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alerts_text.tag_configure("INFO", foreground="black")
        self.alerts_text.tag_configure("WARNING", foreground="orange")
        self.alerts_text.tag_configure("ERROR", foreground="red")
        self.alerts_text.tag_configure("CRITICAL", foreground="red", font=("TkDefaultFont", 10, "bold"))
        self.alerts_text.config(state=tk.DISABLED)

        # Buttons frame
        buttons_frame = ttk.Frame(tab)
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(
            buttons_frame, text="Clear Logs", command=self.clear_logs_gui
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, text="Export Logs", command=self.export_logs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, text="Import Logs", command=self.import_logs
        ).pack(side=tk.LEFT, padx=5)

    def start_auto_refresh(self):
        """Start auto-refresh for logs and alerts"""
        self.refresh_all_logs()  # Initial refresh
        self.schedule_auto_refresh()

    def schedule_auto_refresh(self):
        """Schedule the next auto-refresh"""
        if not self.quit_flag:
            if self.firewall_auto_refresh.get():
                self.refresh_logs()
            if self.iptables_auto_refresh.get():
                self.refresh_iptables()
            if self.alerts_auto_refresh.get():
                self.refresh_alerts()
            # Schedule next refresh in 5 seconds
            self.after(5000, self.schedule_auto_refresh)

    def create_logout_button(self):
        """Create the logout button"""
        # Create a frame at the top of the window
        logout_frame = ttk.Frame(self)
        logout_frame.pack(fill=tk.X, padx=10, pady=5, before=self.tabs)
        
        # Add username label with distinct styling
        username_label = ttk.Label(
            logout_frame,
            text=f"Logged in as: {self.username}",
            font=("TkDefaultFont", 10, "bold")
        )
        username_label.pack(side=tk.LEFT, padx=5)
        
        # Create a logout button with default style
        logout_button = ttk.Button(
            logout_frame,
            text="Logout",
            command=self.logout
        )
        logout_button.pack(side=tk.RIGHT, padx=5)
        
        # Add separator below the logout frame
        separator = ttk.Separator(self, orient='horizontal')
        separator.pack(fill=tk.X, padx=5, pady=2, before=self.tabs)

    def logout(self):
        """Handle user logout"""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?"):
            self.quit_flag = True  # Stop auto-refresh
            log_event(f"User '{self.username}' logged out", "INFO")
            self.destroy()
            main()  # Restart the application

    def on_close(self):
        """Handle window close"""
        if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
            self.quit_flag = True  # Stop auto-refresh
            log_event(f"User '{self.username}' exited application", "INFO")
            self.destroy()

    def create_user_management_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="User Management (Admin)")

        user_frame = ttk.LabelFrame(tab, text="Users")
        user_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.user_listbox = tk.Listbox(user_frame, height=10)
        self.user_listbox.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5), pady=5
        )

        user_buttons = ttk.Frame(user_frame)
        user_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        ttk.Button(user_buttons, text="Add User", command=self.add_user_gui).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(
            user_buttons, text="Remove Selected User", command=self.remove_user_gui
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            user_buttons, text="Refresh User List", command=self.load_users
        ).pack(fill=tk.X, pady=2)

        self.load_users()

    def load_users(self):
        """Load user list into the listbox"""
        self.user_listbox.delete(0, tk.END)
        users = list_users()
        for user_info in users:
            self.user_listbox.insert(
                tk.END, f"{user_info['username']} ({user_info['role']})"
            )

    def add_user_gui(self):
        username = simpledialog.askstring("Add User", "Enter new username:")
        if not username:
            return
        password = simpledialog.askstring(
            "Add User", f"Enter password for {username}:", show="*"
        )
        if not password:
            return
        role = simpledialog.askstring("Add User", "Enter role (admin/user):").lower()
        if role not in ("admin", "user"):
            messagebox.showerror("Invalid Role", "Role must be 'admin' or 'user'.")
            return
        if add_user(username, password, role):
            add_alert(
                f"Admin '{self.username}' added user '{username}' with role '{role}'",
                "INFO",
            )
            log_event(
                f"Admin '{self.username}' added user '{username}' with role '{role}'",
                "INFO",
            )
            messagebox.showinfo("Success", f"User '{username}' added.")
            self.load_users()
        else:
            messagebox.showerror("Error", "Failed to add user. User may already exist.")

    def remove_user_gui(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No user selected.")
            return
        user_info = self.user_listbox.get(selection[0])
        username = user_info.split("(")[0].strip()
        if username == self.username:
            messagebox.showwarning("Action Denied", "You cannot remove yourself.")
            return
        if messagebox.askyesno("Confirm", f"Remove user '{username}'?"):
            if remove_user(username):
                add_alert(
                    f"Admin '{self.username}' removed user '{username}'", "WARNING"
                )
                log_event(
                    f"Admin '{self.username}' removed user '{username}'", "WARNING"
                )
                messagebox.showinfo("Success", f"User '{username}' removed.")
                self.load_users()
            else:
                messagebox.showerror("Error", "Failed to remove user.")

    def create_configuration_tab(self):
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Configuration")

        # Backup/Restore
        backup_frame = ttk.LabelFrame(tab, text="Backup & Restore")
        backup_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            backup_frame, text="Backup Configuration", command=self.backup_config
        ).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(
            backup_frame, text="Restore Configuration", command=self.restore_config
        ).pack(side=tk.LEFT, padx=5, pady=5)

        # Rule Templates
        templates_frame = ttk.LabelFrame(tab, text="Rule Templates")
        templates_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.template_listbox = tk.Listbox(templates_frame, height=5)
        self.template_listbox.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5
        )
        
        template_buttons = ttk.Frame(templates_frame)
        template_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)
        
        ttk.Button(
            template_buttons, text="Add Template", command=self.add_template
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            template_buttons, text="Apply Template", command=self.apply_template
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            template_buttons, text="Delete Template", command=self.delete_template
        ).pack(fill=tk.X, pady=2)

        # Load templates
        self.load_templates()

    def backup_config(self):
        """Backup current configuration"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if filename:
            try:
                config = load_config()
                with open(filename, "w") as f:
                    json.dump(config, f, indent=4)
                messagebox.showinfo("Success", "Configuration backed up successfully!")
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to backup configuration: {str(e)}"
                )

    def restore_config(self):
        """Restore configuration from backup"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "r") as f:
                    config = json.load(f)
                save_config(config)
                messagebox.showinfo("Success", "Configuration restored successfully!")
                self.refresh_all()
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to restore configuration: {str(e)}"
                )

    def load_templates(self):
        """Load rule templates"""
        self.template_listbox.delete(0, tk.END)
        try:
            with open("config/templates.json", "r") as f:
                templates = json.load(f)
                for name in templates:
                    self.template_listbox.insert(tk.END, name)
        except FileNotFoundError:
            pass

    def add_template(self):
        """Add new rule template"""
        name = simpledialog.askstring("Add Template", "Enter template name:")
        if name:
            rules = simpledialog.askstring("Add Template", "Enter rules (JSON format):")
            if rules:
                try:
                    rules_json = json.loads(rules)
                    with open("config/templates.json", "r+") as f:
                        templates = json.load(f)
                        templates[name] = rules_json
                        f.seek(0)
                        json.dump(templates, f, indent=4)
                        f.truncate()
                    self.load_templates()
                    messagebox.showinfo("Success", "Template added successfully!")
                except json.JSONDecodeError:
                    messagebox.showerror("Error", "Invalid JSON format")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to add template: {str(e)}")

    def apply_template(self):
        """Apply selected rule template"""
        selection = self.template_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No template selected.")
            return
        
        template_name = self.template_listbox.get(selection[0])
        try:
            with open("config/templates.json", "r") as f:
                templates = json.load(f)
                if template_name in templates:
                    config = load_config()
                    config.update(templates[template_name])
                    save_config(config)
                    messagebox.showinfo(
                        "Success", f"Template '{template_name}' applied successfully!"
                    )
                    self.refresh_all()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply template: {str(e)}")

    def delete_template(self):
        """Delete selected rule template"""
        selection = self.template_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "No template selected.")
            return
        
        template_name = self.template_listbox.get(selection[0])
        if messagebox.askyesno("Confirm", f"Delete template '{template_name}'?"):
            try:
                with open("config/templates.json", "r+") as f:
                    templates = json.load(f)
                    if template_name in templates:
                        del templates[template_name]
                        f.seek(0)
                        json.dump(templates, f, indent=4)
                        f.truncate()
                self.load_templates()
                messagebox.showinfo("Success", "Template deleted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete template: {str(e)}")

    def refresh_all(self):
        """Refresh all GUI elements"""
            self.load_allowed_ips()
            self.load_blocked_ports()
            self.load_feature_states()
        self.load_users()
        self.load_templates()
        self.refresh_logs()
        self.refresh_alerts()
        self.refresh_iptables()

    def refresh_logs(self):
        """Refresh firewall logs"""
        try:
        logs = view_logs()
        self.firewall_log_text.delete(1.0, tk.END)
            
            # Filter out alert messages and apply styling
            for line in logs.split('\n'):
                if line and "ALERT:" not in line:  # Skip alert messages
                    if "ERROR" in line:
                        self.firewall_log_text.insert(tk.END, line + '\n', "ERROR")
                    elif "WARNING" in line:
                        self.firewall_log_text.insert(tk.END, line + '\n', "WARNING")
                    elif "CRITICAL" in line:
                        self.firewall_log_text.insert(tk.END, line + '\n', "CRITICAL")
                    else:
                        self.firewall_log_text.insert(tk.END, line + '\n', "INFO")
            
            self.firewall_log_text.see(tk.END)
        except Exception as e:
            log_event(f"Error refreshing firewall logs: {str(e)}", "ERROR")

    def refresh_iptables(self):
        """Refresh iptables logs"""
        try:
            logs = show_iptables_logs()
            self.iptables_text.delete(1.0, tk.END)
            
            # Apply styling based on log content
            for line in logs.split('\n'):
                if line:
                    if "DROP" in line:
                        self.iptables_text.insert(tk.END, line + '\n', "DROP")
                    elif "ACCEPT" in line:
                        self.iptables_text.insert(tk.END, line + '\n', "ACCEPT")
                    elif "NEW_CONNECTION" in line:
                        self.iptables_text.insert(tk.END, line + '\n', "NEW")
                    else:
                        self.iptables_text.insert(tk.END, line + '\n')
            
            self.iptables_text.see(tk.END)
        except Exception as e:
            log_event(f"Error refreshing iptables logs: {str(e)}", "ERROR")

    def refresh_alerts(self):
        """Refresh live alerts"""
        try:
            alerts = get_live_alerts()  # This returns a list of dictionaries
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
            
        for alert in alerts:
                if isinstance(alert, dict):
                    message = alert.get('message', '')
                    level = alert.get('level', 'INFO')
                    timestamp = alert.get('timestamp', '')
                    
                    # Convert timestamp to human-readable format
                    if timestamp:
                        try:
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(timestamp)))
                        except (ValueError, TypeError):
                            timestamp = 'Unknown Time'
                    
                    alert_line = f"[{timestamp}] [{level}] {message}\n"
                    
                    if level == "ERROR":
                        self.alerts_text.insert(tk.END, alert_line, "ERROR")
                    elif level == "WARNING":
                        self.alerts_text.insert(tk.END, alert_line, "WARNING")
                    elif level == "CRITICAL":
                        self.alerts_text.insert(tk.END, alert_line, "CRITICAL")
                    else:
                        self.alerts_text.insert(tk.END, alert_line, "INFO")
            
            self.alerts_text.see(tk.END)
            self.alerts_text.config(state=tk.DISABLED)
        except Exception as e:
            log_event(f"Error refreshing alerts: {str(e)}", "ERROR")

    def refresh_all_logs(self):
        """Refresh all logs and alerts"""
        self.refresh_logs()
        self.refresh_iptables()
            self.refresh_alerts()

    def clear_logs_gui(self):
        """Clear all logs"""
        try:
            result = clear_logs()
            if result == "[+] All logs cleared.":
                # Clear the text widgets
                self.firewall_log_text.delete(1.0, tk.END)
                self.iptables_text.delete(1.0, tk.END)
                self.alerts_text.config(state=tk.NORMAL)
                self.alerts_text.delete(1.0, tk.END)
                self.alerts_text.config(state=tk.DISABLED)
                
                add_alert("Logs cleared by user", "INFO")
                log_event("Logs cleared by user", "INFO")
                messagebox.showinfo("Success", "All logs cleared successfully!")
            else:
                messagebox.showerror("Error", f"Failed to clear logs: {result}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
            log_event(f"Error clearing logs: {str(e)}", "ERROR")

    def export_logs(self):
        """Export logs to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if filename:
            try:
                # Get all logs
                firewall_logs = view_logs()
                iptables_logs = show_iptables_logs()
                alerts = get_live_alerts()

                # Write to file
                with open(filename, "w") as f:
                    f.write("=== Firewall Logs ===\n")
                    f.write(firewall_logs)
                    f.write("\n\n=== IPTables Logs ===\n")
                    f.write(iptables_logs)
                    f.write("\n\n=== Live Alerts ===\n")
                    f.write("\n".join(alerts))

                messagebox.showinfo("Success", "Logs exported successfully!")
                add_alert(f"Logs exported to {filename}", "INFO")
                log_event(f"Logs exported to {filename}", "INFO")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def import_logs(self):
        """Import logs from a file"""
        try:
            filename = filedialog.askopenfilename(
                title="Import Logs",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'r') as f:
                    content = f.read()
                    # Parse the imported logs
                    sections = content.split("\n=== ")
                    for section in sections:
                        if section.startswith("Firewall Logs"):
                            self.firewall_log_text.delete(1.0, tk.END)
                            for line in section.split('\n')[1:]:  # Skip the header
                                if line.strip():
                                    self.firewall_log_text.insert(tk.END, line + '\n')
                        elif section.startswith("IPTables Logs"):
                            self.iptables_text.delete(1.0, tk.END)
                            for line in section.split('\n')[1:]:  # Skip the header
                                if line.strip():
                                    self.iptables_text.insert(tk.END, line + '\n')
                        elif section.startswith("Live Alerts"):
                            self.alerts_text.config(state=tk.NORMAL)
                            self.alerts_text.delete(1.0, tk.END)
                            for line in section.split('\n')[1:]:  # Skip the header
                                if line.strip():
                                    self.alerts_text.insert(tk.END, line + '\n')
                            self.alerts_text.config(state=tk.DISABLED)
                    
                    log_event(f"Imported logs from {filename}", "INFO")
                    messagebox.showinfo("Success", "Logs imported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import logs: {e}")
            log_event(f"Failed to import logs: {e}", "ERROR")


def main():
    """Initialize and run the GUI"""
    app = BaselFirewallGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
