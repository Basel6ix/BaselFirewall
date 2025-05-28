import pytest
import subprocess
import time
import socket
from firewall.ids_ips import enable_ids_ips, disable_ids_ips
from firewall.dos import enable_dos_protection, disable_dos_protection
from firewall.alerts import get_live_alerts, clear_alerts
from firewall.logging import view_logs, clear_logs

@pytest.fixture(scope="module", autouse=True)
def setup_protection():
    """Enable protection features for testing"""
    if subprocess.run(["id", "-u"]).stdout.strip() != "0":
        pytest.skip("These tests must be run with sudo")
    
    enable_ids_ips()
    enable_dos_protection()
    clear_alerts()
    clear_logs()
    
    yield
    
    disable_ids_ips()
    disable_dos_protection()

def test_syn_flood_detection():
    """Test detection of SYN flood attacks"""
    target_ip = "127.0.0.1"
    target_port = 80
    
    # Use hping3 to simulate SYN flood
    flood_process = subprocess.Popen([
        "hping3",
        "-S",  # SYN flag
        "-p", str(target_port),
        "--flood",
        target_ip
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Let it run for a few seconds
    time.sleep(5)
    flood_process.terminate()
    
    # Check alerts and logs
    alerts = get_live_alerts()
    logs = view_logs()
    
    assert any("SYN flood" in str(alert).lower() for alert in alerts)
    assert any("SYN flood" in log.lower() for log in logs)

def test_port_scan_detection():
    """Test detection of port scanning"""
    target_ip = "127.0.0.1"
    
    # Use nmap for port scanning
    subprocess.run([
        "nmap",
        "-p-",  # All ports
        "-T4",  # Faster timing
        target_ip
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Check alerts and logs
    alerts = get_live_alerts()
    logs = view_logs()
    
    assert any("port scan" in str(alert).lower() for alert in alerts)
    assert any("port scan" in log.lower() for log in logs)

def test_icmp_flood_detection():
    """Test detection of ICMP flood attacks"""
    target_ip = "127.0.0.1"
    
    # Use hping3 to simulate ICMP flood
    flood_process = subprocess.Popen([
        "hping3",
        "-1",  # ICMP mode
        "--flood",
        target_ip
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Let it run for a few seconds
    time.sleep(5)
    flood_process.terminate()
    
    # Check alerts and logs
    alerts = get_live_alerts()
    logs = view_logs()
    
    assert any("ICMP flood" in str(alert).lower() for alert in alerts)
    assert any("ICMP flood" in log.lower() for log in logs)

def test_connection_limit():
    """Test connection rate limiting"""
    target_ip = "127.0.0.1"
    target_port = 80
    
    # Create multiple connections rapidly
    for _ in range(50):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((target_ip, target_port))
        except (socket.timeout, ConnectionRefusedError):
            pass
        finally:
            sock.close()
    
    # Check alerts and logs
    alerts = get_live_alerts()
    logs = view_logs()
    
    assert any("connection limit" in str(alert).lower() for alert in alerts)
    assert any("connection limit" in log.lower() for log in logs)

def test_unauthorized_access():
    """Test detection of unauthorized access attempts"""
    target_ip = "127.0.0.1"
    blocked_port = 22  # SSH port
    
    # Try to connect to a blocked port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip, blocked_port))
    except (socket.timeout, ConnectionRefusedError):
        pass
    finally:
        sock.close()
    
    # Check alerts and logs
    alerts = get_live_alerts()
    logs = view_logs()
    
    assert any("unauthorized" in str(alert).lower() for alert in alerts)
    assert any("unauthorized" in log.lower() for log in logs)

if __name__ == "__main__":
    pytest.main(["-v", __file__]) 