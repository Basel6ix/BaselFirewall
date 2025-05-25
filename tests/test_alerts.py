import unittest
import os
import json
from firewall.alerts import add_alert, get_live_alerts, clear_alerts
from firewall.config_manager import reset_config

class TestAlertSystem(unittest.TestCase):
    def setUp(self):
        reset_config()
        # Clear any existing alerts
        clear_alerts()

    def tearDown(self):
        reset_config()
        clear_alerts()

    def test_add_alert(self):
        # Test adding a single alert
        test_message = "Test alert message"
        add_alert(test_message, "INFO")
        
        alerts = get_live_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertIn(test_message, alerts[0])
        self.assertIn("INFO", alerts[0])

    def test_add_multiple_alerts(self):
        # Test adding multiple alerts
        messages = [
            ("Alert 1", "INFO"),
            ("Alert 2", "WARNING"),
            ("Alert 3", "ERROR")
        ]
        
        for msg, level in messages:
            add_alert(msg, level)
        
        alerts = get_live_alerts()
        self.assertEqual(len(alerts), 3)
        
        for i, (msg, level) in enumerate(messages):
            self.assertIn(msg, alerts[i])
            self.assertIn(level, alerts[i])

    def test_alert_levels(self):
        # Test different alert levels
        levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]
        
        for level in levels:
            add_alert(f"Test {level} alert", level)
        
        alerts = get_live_alerts()
        self.assertEqual(len(alerts), len(levels))
        
        for i, level in enumerate(levels):
            self.assertIn(level, alerts[i])

    def test_clear_alerts(self):
        # Add some alerts
        add_alert("Test alert 1", "INFO")
        add_alert("Test alert 2", "WARNING")
        
        # Verify alerts were added
        self.assertTrue(len(get_live_alerts()) > 0)
        
        # Clear alerts
        clear_alerts()
        
        # Verify alerts were cleared
        self.assertEqual(len(get_live_alerts()), 0)

    def test_alert_persistence(self):
        # Test that alerts persist between get_live_alerts calls
        add_alert("Persistent alert", "INFO")
        
        # Get alerts multiple times
        alerts1 = get_live_alerts()
        alerts2 = get_live_alerts()
        
        self.assertEqual(alerts1, alerts2)
        self.assertEqual(len(alerts1), 1)

    def test_alert_format(self):
        # Test alert message format
        test_message = "Test alert"
        test_level = "WARNING"
        
        add_alert(test_message, test_level)
        alerts = get_live_alerts()
        
        alert = alerts[0]
        # Alert should contain timestamp, level, and message
        self.assertRegex(alert, r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]")  # Timestamp
        self.assertIn(test_level, alert)
        self.assertIn(test_message, alert)

if __name__ == '__main__':
    unittest.main() 