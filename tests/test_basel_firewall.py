import pytest
import os
import json
import time
import socket
import subprocess
from firewall.auth import authenticate, add_user, remove_user
from firewall.rules import allow_ip, block_ip, block_port, reset_firewall
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.nat import enable_nat, disable_nat
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.logging import log_event, clear_logs, view_logs
from firewall.alerts import add_alert, get_live_alerts, clear_alerts

@pytest.fixture(scope="session", autouse=True)
def setup_firewall():
    """Setup the firewall for testing and cleanup afterward"""
    # Ensure we're running with sudo
    if os.geteuid() != 0:
        pytest.skip("These tests must be run with sudo")
    
    # Reset firewall to known state
    reset_firewall()
    
    # Enable core features
    enable_ids_ips()
    enable_dos_protection()
    enable_stateful_inspection()
    
    yield
    
    # Cleanup
    disable_ids_ips()
    disable_dos_protection()
    disable_stateful_inspection()
    reset_firewall()

@pytest.fixture
def test_user():
    """Create a test user and clean up afterward"""
    username = "testuser"
    password = "TestPass123!"
    success, _ = add_user(username, password, "user")
    assert success
    yield {"username": username, "password": password}
    remove_user(username, "admin")

def test_authentication(test_user):
    """Test user authentication functionality"""
    # Test successful login
    user = authenticate(test_user["username"], test_user["password"])
    assert user is not None
    assert user["username"] == test_user["username"]
    assert user["role"] == "user"
    
    # Test failed login
    assert authenticate(test_user["username"], "wrongpass") is None

def test_firewall_rules():
    """Test firewall rules management"""
    # Test IP rules
    test_ip = "192.168.1.100"
    assert allow_ip(test_ip)
    assert block_ip(test_ip)
    
    # Test port blocking
    test_port = 8080
    assert block_port(test_port)

def test_dos_protection():
    """Test DoS protection features"""
    from firewall.dos import is_connection_rate_exceeded, increment_connection
    
    test_ip = "192.168.1.150"
    
    # Test connection rate limiting
    for _ in range(25):  # Exceed threshold
        increment_connection(test_ip)
    
    assert is_connection_rate_exceeded(test_ip)

def test_ids_ips():
    """Test IDS/IPS functionality"""
    from firewall.ids_ips import _packet_inspector
    
    # Test packet inspection
    test_ip = "192.168.1.200"
    packet = "IP 192.168.1.200.12345 > 192.168.1.1.80: Flags [S]"
    
    # Simulate attack
    for _ in range(35):
        _packet_inspector.inspect_packet(packet, test_ip)
    
    # Check if alerts were generated
    alerts = get_live_alerts()
    assert any(test_ip in str(alert) for alert in alerts)

def test_nat_functionality():
    """Test NAT functionality"""
    # Enable NAT
    assert enable_nat()
    
    # Verify NAT is enabled
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        assert f.read().strip() == "1"
    
    # Disable NAT
    assert disable_nat()

def test_logging_system():
    """Test logging functionality"""
    # Clear logs first
    clear_logs()
    
    # Generate some log events
    test_messages = [
        ("Test info message", "INFO"),
        ("Test warning message", "WARNING"),
        ("Test error message", "ERROR")
    ]
    
    for msg, level in test_messages:
        log_event(msg, level)
    
    # Check logs
    logs = view_logs()
    for msg, _ in test_messages:
        assert any(msg in log for log in logs)

def test_alert_system():
    """Test alert system functionality"""
    # Clear existing alerts
    clear_alerts()
    
    # Add test alerts
    test_alerts = [
        ("Test info alert", "INFO"),
        ("Test warning alert", "WARNING"),
        ("Test critical alert", "CRITICAL")
    ]
    
    for msg, level in test_alerts:
        add_alert(msg, level)
    
    # Check alerts
    alerts = get_live_alerts()
    assert len(alerts) == len(test_alerts)
    for msg, level in test_alerts:
        assert any(msg in str(alert) and level in str(alert) for alert in alerts)

def test_stateful_inspection():
    """Test stateful inspection functionality"""
    # Enable stateful inspection
    assert enable_stateful_inspection()
    
    # Verify it's enabled (check iptables)
    result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
    assert "ESTABLISHED" in result.stdout
    
    # Disable stateful inspection
    assert disable_stateful_inspection()

def test_security_features_integration():
    """Test all security features working together"""
    # Enable all security features
    enable_ids_ips()
    enable_dos_protection()
    enable_stateful_inspection()
    
    # Test IP
    test_ip = "192.168.1.250"
    
    # Add to allowed list
    assert allow_ip(test_ip)
    
    # Block a port
    assert block_port(8080)
    
    # Simulate some traffic
    packet = f"IP {test_ip}.12345 > 192.168.1.1.80: Flags [S]"
    for _ in range(10):
        _packet_inspector.inspect_packet(packet, test_ip)
    
    # Check logs and alerts
    logs = view_logs()
    alerts = get_live_alerts()
    
    assert len(logs) > 0
    assert any(test_ip in log for log in logs)
    
    # Cleanup
    disable_ids_ips()
    disable_dos_protection()
    disable_stateful_inspection()

if __name__ == "__main__":
    pytest.main(["-v", __file__]) 