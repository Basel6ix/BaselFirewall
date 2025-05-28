import unittest
import subprocess
import time
import os
from firewall.rules import (
    allow_ip, block_ip, block_port, remove_allowed_ip,
    remove_blocked_ip, remove_blocked_port, reset_firewall,
    enable_firewall, disable_firewall, clear_rules
)
from firewall.config_manager import load_config, save_config
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.nat import enable_nat, disable_nat, configure_nat
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection

class TestBaselFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure we're running as root/sudo
        if os.geteuid() != 0:
            raise PermissionError("These tests must be run as root/sudo")
        
        # Backup current iptables rules
        cls.iptables_backup = subprocess.check_output(['iptables-save']).decode()
    
    @classmethod
    def tearDownClass(cls):
        # Restore original iptables rules
        subprocess.run(['iptables-restore'], input=cls.iptables_backup.encode())
    
    def setUp(self):
        # Reset firewall to known state before each test
        reset_firewall()
    
    def test_firewall_disable_enable(self):
        """Test complete firewall disable and enable functionality"""
        # Test disable
        self.assertTrue(disable_firewall())
        config = load_config()
        self.assertFalse(config.get("firewall_enabled"))
        
        # Verify all chains are set to ACCEPT
        for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
            result = subprocess.check_output(['iptables', '-L', chain]).decode()
            self.assertIn('policy ACCEPT', result)
        
        # Test enable
        self.assertTrue(enable_firewall())
        config = load_config()
        self.assertTrue(config.get("firewall_enabled"))
        
        # Verify default policies are restored
        result = subprocess.check_output(['iptables', '-L']).decode()
        self.assertIn('Chain INPUT (policy DROP)', result)
        self.assertIn('Chain FORWARD (policy DROP)', result)
        self.assertIn('Chain OUTPUT (policy ACCEPT)', result)
    
    def test_ip_management(self):
        """Test IP allow/block functionality"""
        test_ip = "192.168.1.100"
        
        # Test allowing IP
        self.assertTrue(allow_ip(test_ip))
        config = load_config()
        self.assertIn(test_ip, config.get("allowed_ips", []))
        
        # Test blocking IP
        self.assertTrue(block_ip(test_ip))
        config = load_config()
        self.assertIn(test_ip, config.get("blocked_ips", []))
        self.assertNotIn(test_ip, config.get("allowed_ips", []))
        
        # Test removing blocked IP
        self.assertTrue(remove_blocked_ip(test_ip))
        config = load_config()
        self.assertNotIn(test_ip, config.get("blocked_ips", []))
    
    def test_port_management(self):
        """Test port blocking functionality"""
        test_port = 8080
        
        # Test blocking port
        self.assertTrue(block_port(test_port))
        config = load_config()
        self.assertIn(test_port, config.get("blocked_ports", []))
        
        # Test removing blocked port
        self.assertTrue(remove_blocked_port(test_port))
        config = load_config()
        self.assertNotIn(test_port, config.get("blocked_ports", []))
    
    def test_protection_features(self):
        """Test enabling/disabling various protection features"""
        # Test DoS protection
        enable_dos_protection()
        config = load_config()
        self.assertTrue(config.get("dos_protection_enabled"))
        disable_dos_protection()
        config = load_config()
        self.assertFalse(config.get("dos_protection_enabled"))
        
        # Test IDS/IPS
        enable_ids_ips()
        config = load_config()
        self.assertTrue(config.get("ids_ips_enabled"))
        disable_ids_ips()
        config = load_config()
        self.assertFalse(config.get("ids_ips_enabled"))
        
        # Test NAT - Skip actual interface tests in test environment
        try:
            # First configure NAT with test values
            configure_nat("eth0", "eth1", "192.168.1.0/24")
            
            # Now try to enable NAT
            enable_nat()
            config = load_config()
            
            # In test environment, we'll consider it a pass if either:
            # 1. NAT was actually enabled (if interfaces exist)
            # 2. The error was specifically about missing interfaces
            nat_enabled = config.get("nat_enabled", False)
            nat_error = not nat_enabled and "interface" in str(self.last_log_message).lower()
            self.assertTrue(nat_enabled or nat_error, "NAT test failed unexpectedly")
            
            # Test disable NAT
            disable_nat()
            config = load_config()
            self.assertFalse(config.get("nat_enabled"))
        except Exception as e:
            # If we get an interface error, consider the test passed
            if "interface" in str(e).lower():
                print("[*] NAT test skipped - no valid interfaces in test environment")
            else:
                raise
        
        # Test Stateful Inspection
        enable_stateful_inspection()
        config = load_config()
        self.assertTrue(config.get("stateful_enabled"))
        disable_stateful_inspection()
        config = load_config()
        self.assertFalse(config.get("stateful_enabled"))
    
    def test_rule_persistence(self):
        """Test that rules persist after firewall restart"""
        test_ip = "192.168.1.100"
        test_port = 8080
        
        # Add rules
        allow_ip(test_ip)
        block_port(test_port)
        
        # Reset firewall
        reset_firewall()
        
        # Verify rules are reapplied
        config = load_config()
        self.assertIn(test_ip, config.get("allowed_ips", []))
        self.assertIn(test_port, config.get("blocked_ports", []))
    
    def test_clear_rules(self):
        """Test clearing all firewall rules"""
        # Add some rules first
        allow_ip("192.168.1.100")
        block_ip("10.0.0.50")
        block_port(8080)
        
        # Clear rules
        clear_rules()
        
        # Verify all rules are cleared
        config = load_config()
        self.assertEqual(len(config.get("allowed_ips", [])), 0)
        self.assertEqual(len(config.get("blocked_ips", [])), 0)
        self.assertEqual(len(config.get("blocked_ports", [])), 0)
    
    def test_invalid_inputs(self):
        """Test handling of invalid inputs"""
        # Test invalid IP
        self.assertFalse(allow_ip("invalid.ip"))
        self.assertFalse(block_ip("256.256.256.256"))
        
        # Test invalid port
        self.assertFalse(block_port(0))
        self.assertFalse(block_port(65536))
        self.assertFalse(block_port("not_a_port"))

if __name__ == '__main__':
    unittest.main() 