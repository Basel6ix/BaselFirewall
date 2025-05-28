import pytest
from firewall.utils import is_valid_ip

def test_valid_ip():
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("256.256.256.256") == False
    assert is_valid_ip("invalid") == False

def test_invalid_ip():
    assert is_valid_ip("") == False
    assert is_valid_ip("192.168.1") == False
    assert is_valid_ip("192.168.1.1.1") == False 