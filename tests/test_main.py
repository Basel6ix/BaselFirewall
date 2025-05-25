import sys
import builtins
import pytest
from unittest import mock

sys.path.insert(0, '.')

import main

def test_main_exit(monkeypatch):
    inputs = iter(["0"])  # Select Exit

    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    with pytest.raises(SystemExit) as e:
        main.main()
    assert e.value.code == 0

def test_main_invalid_choice(monkeypatch, capsys):
    inputs = iter(["9", "0"])  # Invalid choice, then exit

    monkeypatch.setattr('builtins.input', lambda _: next(inputs))
    
    with pytest.raises(SystemExit):  # <-- this is the fix
        main.main()
    
    captured = capsys.readouterr()
    assert "Invalid choice" in captured.out


def test_launch_cli_called(monkeypatch):
    inputs = iter(["1", "user", "pass", "0"])  # CLI, user/pass, then exit

    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    with mock.patch('main.launch_cli') as mock_cli, \
         mock.patch('main.launch_gui') as mock_gui:
        mock_cli.side_effect = lambda: print("CLI launched")
        mock_gui.side_effect = lambda: print("GUI launched")

        with pytest.raises(SystemExit):
            main.main()

        mock_cli.assert_called_once()
        mock_gui.assert_not_called()


def test_launch_gui_called(monkeypatch):
    inputs = iter(["2", "0"])  # GUI, then exit

    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    with mock.patch('main.launch_cli') as mock_cli, \
         mock.patch('main.launch_gui') as mock_gui:
        mock_cli.side_effect = lambda: print("CLI launched")
        mock_gui.side_effect = lambda: print("GUI launched")

        with pytest.raises(SystemExit):
            main.main()

        mock_gui.assert_called_once()
        mock_cli.assert_not_called()


def test_main_repeats_after_invalid_choice(monkeypatch, capsys):
    inputs = iter(["9", "0"])  # Invalid, then exit
    monkeypatch.setattr('builtins.input', lambda _: next(inputs))
    
    with pytest.raises(SystemExit):
        main.main()
    captured = capsys.readouterr()
    assert "Invalid choice" in captured.out

def test_cli_auth_failure(monkeypatch):
    inputs = iter(["1", "invalid", "wrong"])  # CLI with bad credentials
    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    with mock.patch('main.launch_cli') as mock_cli:
        mock_cli.side_effect = Exception("Unauthorized")
        with pytest.raises(Exception, match="Unauthorized"):
            main.main()

def test_main_exit(monkeypatch):
    """Test that selecting '0' exits the program cleanly."""
