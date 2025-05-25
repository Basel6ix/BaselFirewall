import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
from firewall import dos

def test_dos_protection_rules():
    assert hasattr(dos, "detect_syn_flood")
    assert hasattr(dos, "detect_icmp_flood")
    assert hasattr(dos, "limit_connection_rate")
