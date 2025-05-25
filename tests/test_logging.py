import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
from firewall import logging as fw_logging

def test_log_event_writes_to_file(tmp_path):
    test_log_file = tmp_path / "firewall.log"

    # Remove old handlers and add a new one pointing to the temp log file
    fw_logging.logger.handlers.clear()
    test_handler = fw_logging.logging.FileHandler(test_log_file)
    formatter = fw_logging.logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    test_handler.setFormatter(formatter)
    fw_logging.logger.addHandler(test_handler)

    fw_logging.log_event("Test event")

    # Flush handlers to make sure logs are written
    for handler in fw_logging.logger.handlers:
        handler.flush()

    with open(test_log_file, 'r') as f:
        contents = f.read()
        assert "Test event" in contents
