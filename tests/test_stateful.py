import unittest
from unittest.mock import patch, MagicMock
import subprocess
from firewall.stateful import enable_stateful_inspection, disable_stateful_inspection, rule_exists
from firewall.config_manager import load_config, reset_config

class TestStatefulInspection(unittest.TestCase):
    def setUp(self):
        reset_config()

    def tearDown(self):
        reset_config()

    @patch('firewall.stateful.rule_exists')
    @patch('firewall.stateful.subprocess.run')
    def test_enable_stateful(self, mock_run, mock_rule_exists):
        # Mock rule check and command execution
        mock_rule_exists.return_value = False  # Rule doesn't exist
        mock_run.return_value = MagicMock(returncode=0)  # Command succeeds
        
        result = enable_stateful_inspection()
        self.assertTrue(result)
        
        # Verify configuration was updated
        config = load_config()
        self.assertTrue(config.get("stateful_enabled", False))
        
        # Verify iptables command was called
        mock_run.assert_called_once()

    @patch('firewall.stateful.rule_exists')
    @patch('firewall.stateful.subprocess.run')
    def test_disable_stateful(self, mock_run, mock_rule_exists):
        # Mock rule check and command execution
        mock_rule_exists.return_value = True  # Rule exists
        mock_run.return_value = MagicMock(returncode=0)  # Command succeeds
        
        result = disable_stateful_inspection()
        self.assertTrue(result)
        
        # Verify configuration was updated
        config = load_config()
        self.assertFalse(config.get("stateful_enabled", True))
        
        # Verify iptables command was called
        mock_run.assert_called_once()

    @patch('firewall.stateful.rule_exists')
    @patch('firewall.stateful.subprocess.run')
    def test_enable_error_handling(self, mock_run, mock_rule_exists):
        # Mock rule check and command failure
        mock_rule_exists.return_value = False  # Rule doesn't exist
        mock_run.side_effect = subprocess.CalledProcessError(1, ["iptables"])
        
        result = enable_stateful_inspection()
        self.assertFalse(result)
        
        # Verify configuration wasn't updated
        config = load_config()
        self.assertFalse(config.get("stateful_enabled", False))

    @patch('firewall.stateful.rule_exists')
    @patch('firewall.stateful.subprocess.run')
    def test_disable_error_handling(self, mock_run, mock_rule_exists):
        # Mock rule check and command failure
        mock_rule_exists.return_value = True  # Rule exists
        mock_run.side_effect = subprocess.CalledProcessError(1, ["iptables"])
        
        result = disable_stateful_inspection()
        self.assertFalse(result)
        
        # Configuration should still be updated when disabling
        config = load_config()
        self.assertFalse(config.get("stateful_enabled", True))

if __name__ == '__main__':
    unittest.main() 