import pytest
import tkinter as tk
from gui.interface import BaselFirewallGUI
from firewall.auth import add_user, remove_user
from firewall.rules import allow_ip, block_port
from firewall.logging import clear_logs
from firewall.alerts import clear_alerts

@pytest.fixture(scope="module")
def setup_test_user():
    """Create a test user for GUI testing"""
    username = "guiuser"
    password = "GuiTest123!"
    success, _ = add_user(username, password, "admin")
    assert success
    yield {"username": username, "password": password}
    remove_user(username, "admin")

@pytest.fixture
def gui_instance(setup_test_user):
    """Create a GUI instance for testing"""
    root = tk.Tk()
    gui = BaselFirewallGUI()
    
    # Login with test user
    gui.login_dialog.username_entry.insert(0, setup_test_user["username"])
    gui.login_dialog.password_entry.insert(0, setup_test_user["password"])
    gui.login_dialog.login()
    
    yield gui
    
    root.destroy()

def test_login_functionality(setup_test_user):
    """Test GUI login functionality"""
    root = tk.Tk()
    gui = BaselFirewallGUI()
    
    # Test successful login
    gui.login_dialog.username_entry.insert(0, setup_test_user["username"])
    gui.login_dialog.password_entry.insert(0, setup_test_user["password"])
    assert gui.login_dialog.login()
    
    # Test failed login
    gui.login_dialog.username_entry.delete(0, tk.END)
    gui.login_dialog.password_entry.delete(0, tk.END)
    gui.login_dialog.username_entry.insert(0, setup_test_user["username"])
    gui.login_dialog.password_entry.insert(0, "wrongpass")
    assert not gui.login_dialog.login()
    
    root.destroy()

def test_firewall_rules_tab(gui_instance):
    """Test firewall rules tab functionality"""
    # Test adding allowed IP
    test_ip = "192.168.1.100"
    gui_instance.ip_entry.insert(0, test_ip)
    gui_instance.add_ip()
    
    # Verify IP was added
    assert test_ip in gui_instance.allowed_ips_listbox.get(0, tk.END)
    
    # Test blocking port
    test_port = "8080"
    gui_instance.port_entry.insert(0, test_port)
    gui_instance.block_port()
    
    # Verify port was blocked
    assert test_port in gui_instance.blocked_ports_listbox.get(0, tk.END)

def test_features_tab(gui_instance):
    """Test features tab functionality"""
    # Test enabling/disabling features
    features = [
        "stateful_inspection",
        "ids_ips",
        "nat",
        "dos_protection"
    ]
    
    for feature in features:
        # Enable feature
        getattr(gui_instance, f"enable_{feature}")()
        assert getattr(gui_instance, f"{feature}_var").get()
        
        # Disable feature
        getattr(gui_instance, f"disable_{feature}")()
        assert not getattr(gui_instance, f"{feature}_var").get()

def test_logs_tab(gui_instance):
    """Test logs and alerts tab functionality"""
    # Clear existing logs and alerts
    clear_logs()
    clear_alerts()
    
    # Generate some activity
    test_ip = "192.168.1.200"
    allow_ip(test_ip)
    block_port(8080)
    
    # Refresh logs
    gui_instance.refresh_logs()
    
    # Verify logs are displayed
    assert len(gui_instance.logs_text.get("1.0", tk.END).strip()) > 0
    
    # Clear logs
    gui_instance.clear_logs()
    gui_instance.refresh_logs()
    
    # Verify logs were cleared
    assert len(gui_instance.logs_text.get("1.0", tk.END).strip()) == 0

def test_user_management_tab(gui_instance):
    """Test user management tab functionality (admin only)"""
    # Test adding a new user
    test_username = "newuser"
    test_password = "NewUser123!"
    
    gui_instance.username_entry.insert(0, test_username)
    gui_instance.password_entry.insert(0, test_password)
    gui_instance.role_var.set("user")
    gui_instance.add_user()
    
    # Verify user was added
    assert test_username in gui_instance.users_listbox.get(0, tk.END)
    
    # Test removing the user
    gui_instance.users_listbox.select_set(
        gui_instance.users_listbox.get(0, tk.END).index(test_username)
    )
    gui_instance.remove_user()
    
    # Verify user was removed
    assert test_username not in gui_instance.users_listbox.get(0, tk.END)

def test_configuration_tab(gui_instance):
    """Test configuration tab functionality"""
    # Test resetting firewall
    gui_instance.reset_firewall()
    
    # Verify lists are empty
    assert len(gui_instance.allowed_ips_listbox.get(0, tk.END)) == 0
    assert len(gui_instance.blocked_ports_listbox.get(0, tk.END)) == 0
    
    # Test clearing logs
    gui_instance.clear_logs()
    gui_instance.refresh_logs()
    
    # Verify logs are cleared
    assert len(gui_instance.logs_text.get("1.0", tk.END).strip()) == 0

if __name__ == "__main__":
    pytest.main(["-v", __file__]) 