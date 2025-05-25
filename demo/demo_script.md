# BaselFirewall Demo Script

## 1. Initial Setup (2 minutes)
```bash
# Install BaselFirewall
git clone https://github.com/Basel6ix/BaselFirewall.git
cd BaselFirewall
sudo python3 setup.py install

# Start the service
sudo systemctl start baselfirewall
```

## 2. GUI Demonstration (5 minutes)

### Login and Interface
1. Launch GUI:
```bash
sudo python3 -m baselfirewall.gui
```
2. Login with admin credentials:
   - Username: admin
   - Password: admin123
3. Show main interface tabs:
   - Firewall Rules
   - Features
   - Logs
   - User Management
   - Configuration

### Basic Firewall Rules
1. Add allowed IP:
   - Go to Firewall Rules tab
   - Click "Add Allowed IP"
   - Enter "192.168.1.100"
2. Block port:
   - Click "Add Blocked Port"
   - Enter "80"
   - Show blocked ports list

## 3. IDS/IPS Detection Demo (5 minutes)

### Setup IDS/IPS
1. Enable IDS/IPS:
   - Go to Features tab
   - Enable IDS/IPS toggle
   - Set sensitivity to "HIGH"

### Test SQL Injection Detection
```bash
# Terminal 1: Watch logs
sudo tail -f /etc/baselfirewall/logs/security.log

# Terminal 2: Simulate attack
curl "http://localhost/login?username=admin' OR '1'='1"
```
- Show alert in GUI
- Demonstrate blocking action

### Test XSS Detection
```bash
# Simulate XSS attack
curl "http://localhost/comment?text=<script>alert('xss')</script>"
```
- Show detection in logs
- Demonstrate prevention

## 4. DoS Protection Demo (5 minutes)

### Configure DoS Protection
1. Enable DoS protection:
   - Go to Features tab
   - Enable DoS Protection
   - Set limits:
     - Max connections: 100
     - Rate limit: 50/sec

### Test DoS Protection
```bash
# Terminal 1: Monitor logs
sudo tail -f /etc/baselfirewall/logs/security.log

# Terminal 2: Simulate DoS attack
ab -n 1000 -c 100 http://localhost/
```
- Show connection blocking
- Demonstrate blacklisting
- View alerts in GUI

## 5. User Management Demo (5 minutes)

### Add New User
1. Go to User Management tab
2. Click "Add User"
3. Enter details:
   - Username: testuser
   - Password: Test123!
   - Role: user
4. Show user in list

### Modify Permissions
1. Select testuser
2. Click "Edit"
3. Modify permissions
4. Save changes

### Test User Access
1. Logout admin
2. Login as testuser
3. Show restricted access
4. Show available features

## 6. Security Features Demo (5 minutes)

### Stateful Inspection
1. Enable feature
2. Show connection tracking
3. Demonstrate state table

### NAT Configuration
1. Configure NAT:
   - External interface: eth0
   - Internal interface: eth1
2. Add port forwarding rule
3. Test connectivity

## 7. Performance Metrics (3 minutes)

### System Resources
```bash
# Show resource usage
sudo baselfirewall-cli health check
```

### Traffic Statistics
1. Show packet processing rate
2. Display connection count
3. Demonstrate throughput

## 8. Logging and Monitoring (3 minutes)

### Log Analysis
1. Show different log types:
   - System logs
   - Security logs
   - Access logs
2. Demonstrate filtering
3. Show export functionality

### Real-time Monitoring
1. Display live alerts
2. Show system status
3. Demonstrate notifications

## 9. Backup and Recovery (2 minutes)

### Configuration Backup
```bash
# Create backup
sudo baselfirewall-cli config backup
```

### Restore Configuration
```bash
# Restore from backup
sudo baselfirewall-cli config restore backup_file.json
```

## Test Scenarios

### 1. IDS/IPS Test Cases
```bash
# Test Case 1: SQL Injection
curl "http://localhost/login?user=admin'--"

# Test Case 2: Path Traversal
curl "http://localhost/file?name=../../../etc/passwd"

# Test Case 3: Command Injection
curl "http://localhost/ping?host=localhost;cat%20/etc/passwd"
```

### 2. DoS Protection Test Cases
```bash
# Test Case 1: Connection Flood
ab -n 5000 -c 200 http://localhost/

# Test Case 2: Slow HTTP
slowhttptest -c 1000 -H -g -o slowhttp -i 10 -r 200 -t GET -u http://localhost

# Test Case 3: SYN Flood
sudo hping3 -S -p 80 --flood localhost
```

### 3. User Management Test Cases
```bash
# Test Case 1: Invalid Login
baselfirewall-cli login wrong_user wrong_pass

# Test Case 2: Permission Escalation
baselfirewall-cli config modify --as-user testuser

# Test Case 3: Password Policy
baselfirewall-cli user add weak_user --password 123
```

mkdir -p resources/screenshots/gui_demo 