import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import getpass
from manage_users import delete_user, reset_password, menu
from firewall.auth import authenticate, load_users, add_user
from firewall.config_manager import reset_config

class TestUserManagement(unittest.TestCase):
    def setUp(self):
        reset_config()
        # Create test user
        self.test_username = "testuser"
        self.test_password = "testpass123"
        add_user(self.test_username, self.test_password, "admin")

    def tearDown(self):
        reset_config()
        # Clean up users file
        users_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'users.json')
        if os.path.exists(users_file):
            os.remove(users_file)

    def test_delete_user(self):
        # Test deleting a user
        with patch('builtins.input', return_value='y'):
            delete_user(self.test_username)
        
        users = load_users()
        self.assertNotIn(self.test_username, users)

    def test_delete_nonexistent_user(self):
        # Test deleting a non-existent user
        with patch('builtins.input') as mock_input:
            delete_user("nonexistent")
            mock_input.assert_not_called()

    @patch('getpass.getpass')
    def test_reset_password(self, mock_getpass):
        # Test resetting password
        new_password = "newpass123"
        mock_getpass.side_effect = [new_password, new_password]
        
        reset_password(self.test_username)
        
        # Verify new password works
        users = load_users()
        auth_result = authenticate(self.test_username, new_password)
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result['username'], self.test_username)

    @patch('getpass.getpass')
    def test_reset_password_mismatch(self, mock_getpass):
        # Test password mismatch during reset
        mock_getpass.side_effect = ["password1", "password2"]
        
        reset_password(self.test_username)
        
        # Original password should still work
        users = load_users()
        auth_result = authenticate(self.test_username, self.test_password)
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result['username'], self.test_username)

    def test_register_user(self):
        # Test registering a new user
        new_username = "newuser"
        new_password = "newpass123"
        
        # Add the new user directly
        success = add_user(new_username, new_password, "user")
        self.assertTrue(success)
        
        # Verify user was created
        users = load_users()
        self.assertIn(new_username, users)
        self.assertEqual(users[new_username]["role"], "user")
        
        # Verify login works
        auth_result = authenticate(new_username, new_password)
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result['username'], new_username)

    def test_register_existing_user(self):
        # Test registering an existing username
        success = add_user(self.test_username, "somepass", "user")
        self.assertFalse(success)
        
        # Verify original user wasn't modified
        users = load_users()
        auth_result = authenticate(self.test_username, self.test_password)
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result['username'], self.test_username)

    @patch('builtins.input')
    def test_menu_delete_user(self, mock_input):
        # Test menu delete user option
        mock_input.side_effect = ["1", self.test_username, "y", "0"]
        
        menu()
        
        users = load_users()
        self.assertNotIn(self.test_username, users)

    @patch('builtins.input')
    @patch('getpass.getpass')
    def test_menu_reset_password(self, mock_getpass, mock_input):
        # Test menu reset password option
        new_password = "newpass123"
        mock_input.side_effect = ["2", self.test_username, "0"]
        mock_getpass.side_effect = [new_password, new_password]
        
        menu()
        
        # Verify new password works
        users = load_users()
        auth_result = authenticate(self.test_username, new_password)
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result['username'], self.test_username)

    @patch('builtins.input')
    def test_menu_invalid_choice(self, mock_input):
        # Test invalid menu choice
        mock_input.side_effect = ["invalid", "0"]
        
        with patch('builtins.print') as mock_print:
            menu()
            mock_print.assert_any_call("Invalid choice.")

if __name__ == '__main__':
    unittest.main() 