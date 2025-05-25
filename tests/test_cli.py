import tempfile
import pytest
import cli.cli as cli_module
from firewall import auth

def test_cli_menu_exit(monkeypatch):
    # Use a temporary login log file
    temp_log = tempfile.NamedTemporaryFile(delete=False)
    monkeypatch.setattr(auth, "LOGIN_LOG_FILE", temp_log.name)

    # Ensure test user exists
    auth.add_user("testuser", "testpass", role="admin")

    # Provide all expected input steps: login + select option 0 + final enter
    inputs = iter(["testuser", "testpass", "0", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    # Expect SystemExit when user selects option 0 (Exit)
    with pytest.raises(SystemExit):
        cli_module.main()
