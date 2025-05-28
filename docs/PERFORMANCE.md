# BaselFirewall Performance Guide

## Performance Metrics

### System Requirements

#### Minimum Requirements
- CPU: 2 cores, 2.0 GHz
- RAM: 2 GB
- Storage: 1 GB
- Network: 100 Mbps NIC

#### Recommended Requirements
- CPU: 4+ cores, 3.0+ GHz
- RAM: 4+ GB
- Storage: 5+ GB SSD
- Network: 1+ Gbps NIC

### Resource Usage

#### CPU Usage
- Idle: 1-2%
- Normal load: 5-10%
- Peak load: 15-25%
- DoS attack: Up to 40%

#### Memory Usage
- Base: 100 MB
- Per 1000 rules: +50 MB
- IDS/IPS: +200 MB
- GUI: +150 MB

#### Network Impact
- Latency overhead: 0.1-1ms
- Throughput impact: 1-5%
- Connection setup: +2-5ms

## Optimization Guidelines

### 1. Rule Optimization

#### Rule Order
```python
# Most used rules first
RULE_PRIORITY = {
    "established_connections": 1,
    "allowed_ips": 2,
    "blocked_ips": 3,
    "custom_rules": 4,
    "default_policy": 5
}
```

#### Rule Consolidation
```python
# Instead of multiple individual IP rules
INDIVIDUAL_RULES = [
    "iptables -A INPUT -s 192.168.1.100 -j ACCEPT",
    "iptables -A INPUT -s 192.168.1.101 -j ACCEPT",
    "iptables -A INPUT -s 192.168.1.102 -j ACCEPT"
]

# Use CIDR notation
OPTIMIZED_RULE = "iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT"
```

### 2. Memory Management

#### Cache Configuration
```python
CACHE_CONFIG = {
    "max_size": 10000,
    "ttl": 3600,
    "cleanup_interval": 300
}
```

#### Connection Tracking
```python
CONNTRACK_SETTINGS = {
    "max_connections": 100000,
    "timeout": {
        "tcp_established": 432000,
        "udp_stream": 180,
        "icmp": 30
    }
}
```

### 3. Logging Optimization

#### Log Rotation
```bash
# /etc/logrotate.d/baselfirewall
/var/log/baselfirewall/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

#### Log Levels
```python
LOG_LEVELS = {
    "production": "WARNING",
    "development": "INFO",
    "debug": "DEBUG"
}
```

### 4. Network Optimization

#### Buffer Sizes
```bash
# /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
```

#### Interface Settings
```bash
# Network interface optimization
ethtool -G eth0 rx 4096 tx 4096
ethtool -K eth0 gso on gro on tso on
```

## Performance Monitoring

### 1. System Metrics

#### CPU Monitoring
```bash
#!/bin/bash
# monitor_cpu.sh
while true; do
    top -b -n 1 | grep "basel_firewall" >> cpu_usage.log
    sleep 60
done
```

#### Memory Monitoring
```bash
#!/bin/bash
# monitor_memory.sh
while true; do
    ps aux | grep "basel_firewall" | awk '{print $6}' >> memory_usage.log
    sleep 60
done
```

### 2. Network Metrics

#### Throughput Monitoring
```bash
#!/bin/bash
# monitor_network.sh
while true; do
    iftop -t -s 10 -L 100 >> network_usage.log
    sleep 60
done
```

#### Connection Tracking
```bash
# Check connection tracking table
cat /proc/net/nf_conntrack | wc -l
```

## Performance Tuning

### 1. Rule Set Optimization

#### Before Optimization
```
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
10000  500K ACCEPT     all  --  *      *       192.168.1.0/24      0.0.0.0/0           
 5000  250K ACCEPT     tcp  --  *      *       0.0.0.0/0           0.0.0.0/0           tcp dpt:80
 2000  100K ACCEPT     tcp  --  *      *       0.0.0.0/0           0.0.0.0/0           tcp dpt:443
```

#### After Optimization
```
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
10000  500K ACCEPT     all  --  *      *       192.168.1.0/24      0.0.0.0/0           
 7000  350K ACCEPT     tcp  --  *      *       0.0.0.0/0           0.0.0.0/0           multiport dports 80,443
```

### 2. System Tuning

#### Kernel Parameters
```bash
# /etc/sysctl.conf
# Network optimization
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000

# Memory optimization
vm.swappiness = 10
vm.vfs_cache_pressure = 50
```

#### Process Priority
```bash
# Set firewall process priority
renice -n -5 -p $(pgrep basel_firewall)
```

## Benchmarking

### 1. Throughput Tests

```bash
# Basic throughput test
iperf3 -c localhost -p 5201 -t 30

# Multi-connection test
iperf3 -c localhost -p 5201 -t 30 -P 4

# UDP test
iperf3 -c localhost -p 5201 -u -b 1G
```

### 2. Latency Tests

```bash
# Basic latency test
ping -c 100 target_host

# TCP connection latency
tcpping target_host 80

# Full route latency
mtr -n target_host
```

### 3. Rule Processing Tests

```bash
# Rule processing benchmark
time iptables -C INPUT -s 192.168.1.1 -j ACCEPT

# Mass rule insertion test
for i in {1..1000}; do
    time iptables -A INPUT -s 192.168.$i.1 -j ACCEPT
done
```

## Performance Troubleshooting

### 1. High CPU Usage

#### Diagnosis
```bash
# Check process CPU usage
top -p $(pgrep basel_firewall)

# Profile Python code
python3 -m cProfile -o profile.stats main.py
```

#### Solution
1. Optimize rule order
2. Increase rule aggregation
3. Adjust logging levels

### 2. Memory Leaks

#### Diagnosis
```bash
# Memory usage over time
ps -o pid,ppid,%mem,rss,cmd -p $(pgrep basel_firewall)

# Python memory profiling
memory_profiler main.py
```

#### Solution
1. Clear connection tracking
2. Adjust cache sizes
3. Implement garbage collection

### 3. Network Bottlenecks

#### Diagnosis
```bash
# Network statistics
netstat -s | grep -i retransmit

# Interface statistics
ethtool -S eth0
```

#### Solution
1. Increase buffer sizes
2. Optimize interface settings
3. Adjust connection timeouts 