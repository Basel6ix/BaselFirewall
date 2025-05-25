import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
import rules

def test_add_and_remove_rule():
    rule = {"id": 1, "action": "allow", "protocol": "tcp", "port": 80}
    rules.clear_rules()
