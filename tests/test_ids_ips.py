import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'firewall')))
from firewall import ids_ips

def test_inspect_packet_initial():
    ip = "1.2.3.4"
    packet = "dummy packet data"

    # Clear state for test IP
    if ip in ids_ips.suspicious_ips:
        del ids_ips.suspicious_ips[ip]

    # First call should not trigger alert (returns None)
    result = ids_ips.inspect_packet(packet, ip)
    assert result is None

def test_inspect_packet_alert_trigger():
    ip = "5.6.7.8"
    packet = "dummy packet data"

    # Setup suspicious_ips to just below threshold
    ids_ips.suspicious_ips[ip]["count"] = 50
    ids_ips.suspicious_ips[ip]["first_seen"] = time.time()
    ids_ips.suspicious_ips[ip]["alerted"] = False

    # This call should trigger the alert because count will go above 50
    result = ids_ips.inspect_packet(packet, ip)
    assert isinstance(result, str)
    assert "ALERT" in result

    # Subsequent calls should not trigger another alert
    result2 = ids_ips.inspect_packet(packet, ip)
    assert result2 is None

def test_suspicious_ips_reset_after_time():
    ip = "9.10.11.12"
    packet = "dummy packet data"

    # Setup suspicious_ips with old timestamp so count resets
    old_time = time.time() - 20  # More than 10 seconds ago
    ids_ips.suspicious_ips[ip]["count"] = 100
    ids_ips.suspicious_ips[ip]["first_seen"] = old_time
    ids_ips.suspicious_ips[ip]["alerted"] = False

    # This call should reset count to 1
    ids_ips.inspect_packet(packet, ip)
    assert ids_ips.suspicious_ips[ip]["count"] == 1

