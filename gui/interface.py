import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from firewall.auth import authenticate, is_admin, add_user, remove_user, list_users, log_login_attempt
from firewall.rules import allow_ip, remove_allowed_ip, block_port, remove_blocked_port
from firewall.config_manager import load_config, reset_config, set_nat_config, save_config
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.nat import enable_nat, disable_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.logging import log_event, view_logs, clear_logs
from firewall.alerts import add_alert, get_live_alerts
import json
import subprocess
import time

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
        
        # Add auto-refresh for alerts
        self.after(1000, self.auto_refresh_alerts)

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
        self.tabs.add(tab, text="Logs & Monitoring")

        # Create notebook for different log types
        log_notebook = ttk.Notebook(tab)
        log_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Firewall Logs
        firewall_log_frame = ttk.Frame(log_notebook)
        log_notebook.add(firewall_log_frame, text="Firewall Logs")
        self.firewall_log_text = tk.Text(firewall_log_frame, height=10, width=80)
        self.firewall_log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Alerts
        alerts_frame = ttk.Frame(log_notebook)
        log_notebook.add(alerts_frame, text="Alerts")
        self.alerts_text = tk.Text(alerts_frame, height=10, width=80)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Traffic Monitoring
        traffic_frame = ttk.Frame(log_notebook)
        log_notebook.add(traffic_frame, text="Traffic Monitor")
        
        # Traffic graph
        self.traffic_canvas = tk.Canvas(traffic_frame, height=200, width=600)
        self.traffic_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Traffic stats
        stats_frame = ttk.Frame(traffic_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        self.packets_label = ttk.Label(stats_frame, text="Packets: 0")
        self.packets_label.pack(side=tk.LEFT, padx=5)
        
        self.bytes_label = ttk.Label(stats_frame, text="Bytes: 0")
        self.bytes_label.pack(side=tk.LEFT, padx=5)
        
        self.connections_label = ttk.Label(stats_frame, text="Active Connections: 0")
        self.connections_label.pack(side=tk.LEFT, padx=5)

        # Buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)

        # Start monitoring
        self.start_traffic_monitoring()

    def start_traffic_monitoring(self):
        """Start real-time traffic monitoring"""
        self.traffic_data = {
            'time': [],
            'packets': [],
            'bytes': []
        }
        self.update_traffic_graph()
        self.after(1000, self.update_traffic_stats)

    def update_traffic_graph(self):
        """Update the traffic graph"""
        self.traffic_canvas.delete("all")
        
        if len(self.traffic_data['time']) > 1:
            # Calculate scaling factors
            max_packets = max(self.traffic_data['packets']) if self.traffic_data['packets'] else 1
            max_bytes = max(self.traffic_data['bytes']) if self.traffic_data['bytes'] else 1
            
            # Draw packets line
            points = []
            for i, (t, p) in enumerate(zip(self.traffic_data['time'], self.traffic_data['packets'])):
                x = i * (600 / len(self.traffic_data['time']))
                y = 200 - (p * 200 / max_packets)
                points.extend([x, y])
            
            if points:
                self.traffic_canvas.create_line(points, fill='blue', width=2)
            
            # Draw bytes line
            points = []
            for i, (t, b) in enumerate(zip(self.traffic_data['time'], self.traffic_data['bytes'])):
                x = i * (600 / len(self.traffic_data['time']))
                y = 200 - (b * 200 / max_bytes)
                points.extend([x, y])
            
            if points:
                self.traffic_canvas.create_line(points, fill='red', width=2)
        
        self.after(1000, self.update_traffic_graph)

    def update_traffic_stats(self):
        """Update traffic statistics"""
        try:
            # Get current traffic stats
            result = subprocess.run(['iptables', '-L', '-v', '-n'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            total_packets = 0
            total_bytes = 0
            active_connections = 0
            
            for line in lines:
                if 'packets' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        total_packets += int(parts[0])
                        total_bytes += int(parts[1])
            
            # Get active connections
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            active_connections = len([l for l in result.stdout.split('\n') if 'ESTABLISHED' in l])
            
            # Update labels
            self.packets_label.config(text=f"Packets: {total_packets}")
            self.bytes_label.config(text=f"Bytes: {total_bytes}")
            self.connections_label.config(text=f"Active Connections: {active_connections}")
            
            # Update graph data
            self.traffic_data['time'].append(time.time())
            self.traffic_data['packets'].append(total_packets)
            self.traffic_data['bytes'].append(total_bytes)
            
            # Keep only last 60 seconds
            current_time = time.time()
            self.traffic_data['time'] = [t for t in self.traffic_data['time'] if current_time - t <= 60]
            self.traffic_data['packets'] = self.traffic_data['packets'][-len(self.traffic_data['time']):]
            self.traffic_data['bytes'] = self.traffic_data['bytes'][-len(self.traffic_data['time']):]
            
        except Exception as e:
            log_event(f"Error updating traffic stats: {str(e)}", "ERROR")
        
        self.after(1000, self.update_traffic_stats)

    def export_logs(self):
        """Export logs to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("=== Firewall Logs ===\n")
                    f.write(self.firewall_log_text.get("1.0", tk.END))
                    f.write("\n=== Alerts ===\n")
                    f.write(self.alerts_text.get("1.0", tk.END))
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

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
        self.tabs.add(tab, text="Configuration")

        # Backup/Restore
        backup_frame = ttk.LabelFrame(tab, text="Backup & Restore")
        backup_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(backup_frame, text="Backup Configuration", command=self.backup_config).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(backup_frame, text="Restore Configuration", command=self.restore_config).pack(side=tk.LEFT, padx=5, pady=5)

        # Rule Templates
        templates_frame = ttk.LabelFrame(tab, text="Rule Templates")
        templates_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.template_listbox = tk.Listbox(templates_frame, height=5)
        self.template_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        template_buttons = ttk.Frame(templates_frame)
        template_buttons.pack(side=tk.LEFT, fill=tk.Y, pady=5)
        
        ttk.Button(template_buttons, text="Add Template", command=self.add_template).pack(fill=tk.X, pady=2)
        ttk.Button(template_buttons, text="Apply Template", command=self.apply_template).pack(fill=tk.X, pady=2)
        ttk.Button(template_buttons, text="Delete Template", command=self.delete_template).pack(fill=tk.X, pady=2)

        # Load templates
        self.load_templates()

    def backup_config(self):
        """Backup current configuration"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                config = load_config()
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=4)
                messagebox.showinfo("Success", "Configuration backed up successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to backup configuration: {str(e)}")

    def restore_config(self):
        """Restore configuration from backup"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    config = json.load(f)
                save_config(config)
                messagebox.showinfo("Success", "Configuration restored successfully!")
                self.refresh_all()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore configuration: {str(e)}")

    def load_templates(self):
        """Load rule templates"""
        self.template_listbox.delete(0, tk.END)
        try:
            with open('config/templates.json', 'r') as f:
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
                    with open('config/templates.json', 'r+') as f:
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
            with open('config/templates.json', 'r') as f:
                templates = json.load(f)
                if template_name in templates:
                    config = load_config()
                    config.update(templates[template_name])
                    save_config(config)
                    messagebox.showinfo("Success", f"Template '{template_name}' applied successfully!")
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
                with open('config/templates.json', 'r+') as f:
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

    def refresh_logs(self):
        logs = view_logs()
        self.firewall_log_text.config(state=tk.NORMAL)
        self.firewall_log_text.delete(1.0, tk.END)
        self.firewall_log_text.insert(tk.END, logs)
        self.firewall_log_text.config(state=tk.DISABLED)

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

    def auto_refresh_alerts(self):
        """Auto refresh alerts every second"""
        if hasattr(self, 'alerts_text'):
            self.refresh_alerts()
        self.after(1000, self.auto_refresh_alerts)


if __name__ == "__main__":
    app = BaselFirewallGUI()
    app.mainloop()
