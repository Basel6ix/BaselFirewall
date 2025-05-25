import pytest
import os
import json
import time
from firewall.auth import authenticate, add_user, remove_user
from firewall.rules import allow_ip, block_ip, block_port
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.dos import enable_dos_protection, disable_dos_protection

@pytest.fixture
def setup_test_user():
    # Add test user
    success, _ = add_user("testuser", "testpass123", "user")
    assert success
    yield "testuser"
    # Cleanup
    remove_user("testuser", "admin")

@pytest.fixture
def setup_firewall():
    # Enable core features
    enable_ids_ips()
    enable_dos_protection()
    yield
    # Cleanup
    disable_ids_ips()
    disable_dos_protection()

def test_authentication_flow():
    # Test user registration and authentication
    success, msg = add_user("integtest", "Password123!", "user")
    assert success, msg

    # Test successful authentication
    user = authenticate("integtest", "Password123!")
    assert user is not None
    assert user["username"] == "integtest"
    assert user["role"] == "user"

    # Test failed authentication
    user = authenticate("integtest", "wrongpass")
    assert user is None

    # Cleanup
    remove_user("integtest", "admin")

def test_firewall_rules(setup_firewall):
    # Test IP rules
    test_ip = "192.168.1.100"
    assert allow_ip(test_ip)
    
    config_file = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    assert test_ip in config["allowed_ips"]
    
    # Test blocking the same IP
    assert block_ip(test_ip)
    with open(config_file, 'r') as f:
        config = json.load(f)
    assert test_ip in config["blocked_ips"]
    assert test_ip not in config["allowed_ips"]

def test_port_blocking(setup_firewall):
    # Test port blocking
    test_port = 8080
    assert block_port(test_port)
    
    config_file = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    assert test_port in config["blocked_ports"]

def test_ids_ips_integration(setup_firewall):
    from firewall.ids_ips import _packet_inspector
    
    # Test packet inspection
    test_ip = "192.168.1.200"
    packet = "IP 192.168.1.200.12345 > 192.168.1.1.80: Flags [S]"
    
    # Simulate SYN flood
    for _ in range(35):  # Above SYN flood threshold
        _packet_inspector.inspect_packet(packet, test_ip)
    
    # Check if IP was blocked
    config_file = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    assert test_ip in config["blocked_ips"]

def test_dos_protection(setup_firewall):
    from firewall.dos import is_connection_rate_exceeded, increment_connection
    
    test_ip = "192.168.1.150"
    
    # Simulate multiple connections
    for _ in range(25):  # Above max_connections threshold
        increment_connection(test_ip)
    
    assert is_connection_rate_exceeded(test_ip)

def test_feature_integration(setup_firewall):
    # Test that all features work together
    test_ip = "192.168.1.250"
    
    # Add IP to allowed list
    assert allow_ip(test_ip)
    
    # Block a port
    assert block_port(8080)
    
    # Enable all features
    enable_ids_ips()
    enable_dos_protection()
    
    # Verify configuration
    config_file = os.path.join(os.path.dirname(__file__), '../config/firewall_config.json')
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    assert test_ip in config["allowed_ips"]
    assert 8080 in config["blocked_ports"]
    
    # Cleanup
    disable_ids_ips()
    disable_dos_protection() 