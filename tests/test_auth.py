import pytest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
import auth

def test_add_and_authenticate_user():
    username = "testuser"
    password = "testpass"
    # Cleanup if user exists
    users = auth.load_users()
    users.pop(username, None)
    auth.save_users(users)

    # Add user
    success, msg = auth.add_user(username, password)
    assert success

    # Authenticate correct password
    user = auth.authenticate(username, password)
    assert user is not None
    assert user['username'] == username

    # Authenticate wrong password
    assert auth.authenticate(username, "wrongpass") is None

    # Remove user
    assert auth.remove_user(username)

def test_change_password():
    username = "testuser2"
    password = "oldpass"
    new_password = "newpass"

    # Setup user
    users = auth.load_users()
    users.pop(username, None)
    auth.save_users(users)
    auth.add_user(username, password)

    # Change password with wrong old password
    success, msg = auth.change_password(username, "badold", new_password)
    assert not success

    # Change password with correct old password
    success, msg = auth.change_password(username, password, new_password)
    assert success

    # Authenticate with new password
    user = auth.authenticate(username, new_password)
    assert user is not None

    auth.remove_user(username)
