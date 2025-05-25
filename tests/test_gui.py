import unittest
from unittest.mock import MagicMock, patch
from gui.interface import BaselFirewallGUI, LoginDialog
from firewall.auth import add_user, remove_user
from firewall.config_manager import reset_config, load_config

class TestBaselFirewallGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create test user
        cls.test_username = "testgui"
        cls.test_password = "testpass123"
        add_user(cls.test_username, cls.test_password, "admin")

    @classmethod
    def tearDownClass(cls):
        # Cleanup test user
        remove_user(cls.test_username)
        reset_config()

    def setUp(self):
        # Mock root window
        self.root_patcher = patch('tkinter.Tk')
        self.mock_tk = self.root_patcher.start()
        self.root = self.mock_tk.return_value
        self.root.withdraw = MagicMock()
        
        # Mock notebook
        self.notebook_patcher = patch('tkinter.ttk.Notebook')
        self.mock_notebook = self.notebook_patcher.start()
        self.notebook = self.mock_notebook.return_value
        self.notebook.add = MagicMock()
        
        # Mock listboxes and text widgets
        self.mock_listbox = MagicMock()
        self.mock_listbox.get = MagicMock(return_value=[])
        self.mock_text = MagicMock()
        
        self.gui = None

    def tearDown(self):
        if self.gui and not getattr(self.gui, '_is_destroyed', False):
            self.gui.destroy()
        self.root_patcher.stop()
        self.notebook_patcher.stop()

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_login(self, mock_auth, mock_dialog):
        # Mock successful login
        mock_auth.return_value = {'username': self.test_username, 'role': 'admin'}
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = self.test_username
        mock_dialog_instance.password = self.test_password
        mock_dialog.return_value = mock_dialog_instance
        
        with patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            self.assertTrue(hasattr(self.gui, 'username'))
            self.assertTrue(hasattr(self.gui, 'admin'))

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_failed_login(self, mock_auth, mock_dialog):
        # Mock failed login then cancel
        mock_auth.return_value = None
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = "invalid"
        mock_dialog_instance.password = "invalid"
        
        # First attempt: failed login
        first_dialog = MagicMock()
        first_dialog.username = "invalid"
        first_dialog.password = "invalid"
        
        # Second attempt: cancel login
        second_dialog = MagicMock()
        second_dialog.username = None
        second_dialog.password = None
        
        mock_dialog.side_effect = [first_dialog, second_dialog]
        
        with patch('tkinter.messagebox.showerror') as mock_error, \
             patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            self.gui._is_destroyed = True  # Mark as destroyed since login was cancelled
            mock_error.assert_called_with("Login Failed", "Invalid username or password.")
            mock_dialog.assert_called()
            self.assertEqual(mock_dialog.call_count, 2)

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_firewall_rules_tab(self, mock_auth, mock_dialog):
        # Mock successful login
        mock_auth.return_value = {'username': self.test_username, 'role': 'admin'}
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = self.test_username
        mock_dialog_instance.password = self.test_password
        mock_dialog.return_value = mock_dialog_instance
        
        with patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            
            # Test adding allowed IP
            with patch('tkinter.simpledialog.askstring') as mock_input:
                mock_input.return_value = "192.168.1.100"
                self.gui.add_allowed_ip_gui()
                
            # Verify IP was added to config
            config = load_config()
            self.assertIn("192.168.1.100", config.get("allowed_ips", []))

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_features_tab(self, mock_auth, mock_dialog):
        # Mock successful login
        mock_auth.return_value = {'username': self.test_username, 'role': 'admin'}
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = self.test_username
        mock_dialog_instance.password = self.test_password
        mock_dialog.return_value = mock_dialog_instance
        
        with patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            
            # Test IDS/IPS toggle
            self.gui.ids_ips_var.set(True)
            self.gui.toggle_ids_ips()
            config = load_config()
            self.assertTrue(config.get("ids_ips_enabled"))
            
            # Test DoS protection toggle
            self.gui.dos_var.set(True)
            self.gui.toggle_dos()
            config = load_config()
            self.assertTrue(config.get("dos_protection_enabled"))

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_logs_tab(self, mock_auth, mock_dialog):
        # Mock successful login
        mock_auth.return_value = {'username': self.test_username, 'role': 'admin'}
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = self.test_username
        mock_dialog_instance.password = self.test_password
        mock_dialog.return_value = mock_dialog_instance
        
        with patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            
            # Test log refresh
            with patch('gui.interface.view_logs') as mock_logs:
                mock_logs.return_value = "Test log entry"
                self.gui.refresh_logs()
                self.mock_text.delete.assert_called()
                self.mock_text.insert.assert_called_with("end", "Test log entry")

    @patch('gui.interface.LoginDialog')
    @patch('gui.interface.authenticate')
    def test_user_management(self, mock_auth, mock_dialog):
        # Mock successful login as admin
        mock_auth.return_value = {'username': self.test_username, 'role': 'admin'}
        mock_dialog_instance = MagicMock()
        mock_dialog_instance.username = self.test_username
        mock_dialog_instance.password = self.test_password
        mock_dialog.return_value = mock_dialog_instance
        
        with patch('tkinter.ttk.Frame'), \
             patch('tkinter.Listbox', return_value=self.mock_listbox), \
             patch('tkinter.Text', return_value=self.mock_text):
            self.gui = BaselFirewallGUI()
            self.gui.admin = True
            
            # Test user listing
            self.gui.load_users()
            self.mock_listbox.delete.assert_called()
            self.mock_listbox.insert.assert_called()

if __name__ == '__main__':
    unittest.main() 