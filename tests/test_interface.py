import pytest
import sys
import os
import tempfile
import firewall.auth as auth
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from gui import interface as interface_module


def test_gui_start_and_close(monkeypatch):
    # Patch the LOGIN_LOG_FILE to a writable temporary file
    temp_log = tempfile.NamedTemporaryFile(delete=False)
    monkeypatch.setattr(auth, "LOGIN_LOG_FILE", temp_log.name)

    # Ensure GUI starts and closes without raising exceptions
    gui = interface_module.BaselFirewallGUI()
    gui.destroy()  # Clean up the GUI window
