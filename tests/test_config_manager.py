import pytest
import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
import config_manager

def test_load_and_save_config(tmp_path):
    test_config_file = tmp_path / "config.json"
    config_manager.CONFIG_FILE = str(test_config_file)

    test_data = {"key": "value"}
    config_manager.save_config(test_data)
    loaded = config_manager.load_config()
    assert loaded == test_data
