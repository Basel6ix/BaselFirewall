import unittest
import os
import sys
import json
import time
import pytest
import socket
from firewall.rules import (
    apply_firewall_rules,
    allow_ip,
    block_ip,
    block_port,
    remove_allowed_ip,
    remove_blocked_ip,
    remove_blocked_port,
)
from firewall.nat import enable_nat, disable_nat, configure_nat
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection
from firewall.config_manager import load_config, save_config, reset_config
from firewall.logging import log_event, view_logs, clear_logs
from firewall.alerts import add_alert, get_live_alerts, clear_alerts


class TestBaselFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure we're running as root/sudo
        if os.geteuid() != 0:
            raise PermissionError("These tests must be run as root/sudo")

        # Save original config
        cls.original_config = load_config()

        # Reset firewall to known state
        reset_config()
        clear_logs()
        clear_alerts()

    def setUp(self):
        # Reset before each test
        reset_config()
        clear_logs()
        clear_alerts()

    def test_basic_rules(self):
        """Test basic firewall rules functionality"""
        # Test allowing an IP
        self.assertTrue(allow_ip("192.168.1.100"))
        config = load_config()
        self.assertIn("192.168.1.100", config["allowed_ips"])

        # Test blocking an IP
        self.assertTrue(block_ip("10.0.0.50"))
        config = load_config()
        self.assertIn("10.0.0.50", config["blocked_ips"])

        # Test blocking a port
        self.assertTrue(block_port(8080))
        config = load_config()
        self.assertIn(8080, config["blocked_ports"])

    def test_nat_functionality(self):
        """Test NAT enable/disable functionality"""
        # Configure NAT first
        self.assertTrue(configure_nat("eth0", "lo", "192.168.1.0/24"))

        # Enable NAT
        self.assertTrue(enable_nat())
        config = load_config()
        self.assertTrue(config["nat_enabled"])

        # Disable NAT
        self.assertTrue(disable_nat())
        config = load_config()
        self.assertFalse(config["nat_enabled"])

    def test_dos_protection(self):
        """Test DoS protection functionality"""
        # Enable DoS protection
        self.assertTrue(enable_dos_protection())
        config = load_config()
        self.assertTrue(config["dos_protection_enabled"])

        # Disable DoS protection
        self.assertTrue(disable_dos_protection())
        config = load_config()
        self.assertFalse(config["dos_protection_enabled"])

    def test_ids_ips(self):
        """Test IDS/IPS functionality"""
        # Enable IDS/IPS
        self.assertTrue(enable_ids_ips())
        config = load_config()
        self.assertTrue(config["ids_ips_enabled"])

        # Disable IDS/IPS
        self.assertTrue(disable_ids_ips())
        config = load_config()
        self.assertFalse(config["ids_ips_enabled"])

    def test_stateful_inspection(self):
        """Test stateful inspection functionality"""
        # Enable stateful inspection
        self.assertTrue(enable_stateful_inspection())
        config = load_config()
        self.assertTrue(config["stateful_enabled"])

        # Disable stateful inspection
        self.assertTrue(disable_stateful_inspection())
        config = load_config()
        self.assertFalse(config["stateful_enabled"])

    def test_logging_and_alerts(self):
        """Test logging and alert functionality"""
        # Test logging
        log_event("Test log message", "INFO")
        logs = view_logs()
        self.assertIn("Test log message", logs)

        # Test alerts
        add_alert("Test alert", "WARNING")
        alerts = get_live_alerts()
        self.assertTrue(any("Test alert" in alert for alert in alerts))

    def test_rule_removal(self):
        """Test removal of firewall rules"""
        # Add and then remove an allowed IP
        allow_ip("192.168.1.200")
        self.assertTrue(remove_allowed_ip("192.168.1.200"))
        config = load_config()
        self.assertNotIn("192.168.1.200", config["allowed_ips"])

        # Add and then remove a blocked IP
        block_ip("10.0.0.100")
        self.assertTrue(remove_blocked_ip("10.0.0.100"))
        config = load_config()
        self.assertNotIn("10.0.0.100", config["blocked_ips"])

        # Add and then remove a blocked port
        block_port(443)
        self.assertTrue(remove_blocked_port(443))
        config = load_config()
        self.assertNotIn(443, config["blocked_ports"])

    def test_config_persistence(self):
        """Test configuration persistence"""
        # Make some changes
        allow_ip("192.168.1.150")
        block_port(22)

        # Configure and enable NAT
        configure_nat("eth0", "lo", "192.168.1.0/24")
        enable_nat()

        # Load config and verify changes
        config = load_config()
        self.assertIn("192.168.1.150", config["allowed_ips"])
        self.assertIn(22, config["blocked_ports"])
        self.assertTrue(config["nat_enabled"])

    def test_invalid_inputs(self):
        """Test handling of invalid inputs"""
        # Test invalid IP
        self.assertFalse(allow_ip("invalid.ip"))
        self.assertFalse(block_ip("256.256.256.256"))

        # Test invalid port
        self.assertFalse(block_port(65536))
        self.assertFalse(block_port(-1))
        self.assertFalse(block_port("not_a_port"))

    def test_firewall_reset(self):
        """Test firewall reset functionality"""
        # Make some changes
        allow_ip("192.168.1.250")
        block_port(80)
        enable_nat()

        # Reset configuration
        reset_config()
        disable_nat()  # Explicitly disable NAT after reset

        # Verify reset
        config = load_config()
        self.assertEqual(config["allowed_ips"], [])
        self.assertEqual(config["blocked_ports"], [])
        self.assertFalse(config["nat_enabled"])

    @classmethod
    def tearDownClass(cls):
        # Restore original configuration
        save_config(cls.original_config)

        # Disable all features
        disable_nat()
        disable_dos_protection()
        disable_ids_ips()
        disable_stateful_inspection()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: These tests must be run as root/sudo")
        sys.exit(1)
    unittest.main()
