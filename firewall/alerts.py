import time
from collections import OrderedDict
from firewall.logging import log_event

# Use OrderedDict for alert buffer to maintain order and implement deduplication
_alert_buffer = OrderedDict()
_alert_history = OrderedDict()
MAX_BUFFER_SIZE = 1000
DEDUP_WINDOW = 300  # 5 minutes in seconds


def _clean_old_alerts():
    """Remove alerts older than the deduplication window"""
    now = time.time()
    cutoff = now - DEDUP_WINDOW

    # Clean alert history
    for timestamp in list(_alert_history.keys()):
        if timestamp < cutoff:
            del _alert_history[timestamp]


def _is_duplicate(message, level):
    """Check if this alert is a duplicate within the deduplication window"""
    now = time.time()
    alert_key = f"{message}:{level}"

    # Check recent history
    for timestamp, stored_key in _alert_history.items():
        if stored_key == alert_key:
            return True

    # Add to history
    _alert_history[now] = alert_key
    return False


def add_alert(message, level="INFO", deduplicate=True):
    """
    Add an alert to the buffer with deduplication

    Args:
        message (str): Alert message
        level (str): Alert level (INFO, WARNING, ERROR, CRITICAL)
        deduplicate (bool): Whether to check for and prevent duplicate alerts
    """
    try:
        now = time.time()

        # Clean old alerts first
        _clean_old_alerts()

        # Check for duplicates if enabled
        if deduplicate and _is_duplicate(message, level):
            return

        # Add to buffer with timestamp
        _alert_buffer[now] = {"message": message, "level": level, "timestamp": now}

        # Trim buffer if needed
        while len(_alert_buffer) > MAX_BUFFER_SIZE:
            _alert_buffer.popitem(last=False)

        # Log the alert (but don't create duplicate logs)
        log_event(message, level, category="ALERT")

    except Exception as e:
        # Fallback logging in case of errors
        log_event(f"Error adding alert: {str(e)}", "ERROR")


def get_live_alerts(count=10, min_level="INFO"):
    """
    Get recent alerts with level filtering

    Args:
        count (int): Number of alerts to return
        min_level (str): Minimum alert level to include
    """
    level_priority = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}
    min_priority = level_priority.get(min_level.upper(), 0)

    filtered_alerts = [
        alert
        for alert in _alert_buffer.values()
        if level_priority.get(alert["level"].upper(), 0) >= min_priority
    ]

    return filtered_alerts[-count:]


def clear_alerts():
    """Clear all alerts from the buffer"""
    global _alert_buffer, _alert_history
    _alert_buffer.clear()
    _alert_history.clear()
    log_event("Alert buffer cleared", "INFO", category="ALERT")


def get_alert_stats():
    """Get statistics about current alerts"""
    stats = {
        "total": len(_alert_buffer),
        "by_level": {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
    }

    for alert in _alert_buffer.values():
        level = alert["level"].upper()
        if level in stats["by_level"]:
            stats["by_level"][level] += 1

    return stats


def view_alerts():
    print("=== Alert Log ===")
    if not _alert_buffer:
        print("No alerts.")
    for alert in _alert_buffer.values():
        print(f"[{alert['timestamp']}] [{alert['level'].upper()}] {alert['message']}")
