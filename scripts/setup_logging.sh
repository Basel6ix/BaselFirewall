#!/bin/bash

# Create log directory
sudo mkdir -p /var/log/baselfirewall

# Create logrotate configuration
sudo tee /etc/logrotate.d/baselfirewall << EOF
/var/log/baselfirewall/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload baselfirewall
    endscript
}
EOF

# Create systemd service for log forwarding
sudo tee /etc/systemd/system/baselfirewall-logger.service << EOF
[Unit]
Description=BaselFirewall Log Forwarder
After=baselfirewall.service

[Service]
Type=simple
ExecStart=/bin/sh -c 'journalctl -f -u baselfirewall | grep -E "DROPPED_|ALERT:|baselfirewall" > /var/log/baselfirewall/firewall.log'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
sudo chown -R root:root /var/log/baselfirewall
sudo chmod -R 640 /var/log/baselfirewall

# Create log files
sudo touch /var/log/baselfirewall/{dropped,alerts,firewall}.log
sudo chmod 640 /var/log/baselfirewall/*.log

# Enable and start the logger service
sudo systemctl daemon-reload
sudo systemctl enable baselfirewall-logger
sudo systemctl start baselfirewall-logger

echo "Logging setup complete. Logs will be stored in /var/log/baselfirewall/" 