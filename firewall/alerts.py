from datetime import datetime
from firewall.logging import log_event

alert_buffer = []

def add_alert(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] [{level.upper()}] {message}"

    if len(alert_buffer) >= 100:
        alert_buffer.pop(0)
    alert_buffer.append(formatted)

    log_event(message, level)

def get_live_alerts():
    return alert_buffer

def view_alerts():
    print("=== Alert Log ===")
    if not alert_buffer:
        print("No alerts.")
    for alert in alert_buffer:
        print(alert)

def clear_alerts():
    """Clear all alerts from the buffer"""
    global alert_buffer
    alert_buffer = []
    log_event("Alert buffer cleared", "INFO")
