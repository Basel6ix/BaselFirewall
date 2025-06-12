# BaselFirewall Rule Templates
## Comprehensive Security Profiles

---

## Overview

- Pre-configured security profiles
- Easy-to-apply templates
- Customizable settings
- Real-world use cases

---

## Template Categories

1. Web Server Template
2. Database Server Template
3. Development Template
4. High Security Template
5. VMware Attacker Block Template

---

## Web Server Template

### Configuration:
- Allowed Ports: 80 (HTTP), 443 (HTTPS)
- Blocked Ports: 22 (SSH), 23 (Telnet), 25 (SMTP)
- Security Features:
  * DoS Protection: Enabled
  * IDS/IPS: Enabled
  * Stateful Inspection: Enabled

### Use Case:
- Public-facing web servers
- Web applications
- Content delivery

---

## Database Server Template

### Configuration:
- Allowed Ports: 3306 (MySQL), 5432 (PostgreSQL)
- Blocked Ports: 80, 443, 22
- Security Features:
  * DoS Protection: Enabled
  * IDS/IPS: Enabled
  * Stateful Inspection: Enabled

### Use Case:
- Database servers
- Data warehouses
- Backend services

---

## Development Template

### Configuration:
- Allowed Ports: 22, 80, 443, 3000, 8000, 8080
- Blocked Ports: None
- Security Features:
  * DoS Protection: Disabled
  * IDS/IPS: Enabled
  * Stateful Inspection: Enabled

### Use Case:
- Development environments
- Testing servers
- Local development

---

## High Security Template

### Configuration:
- Allowed Ports: 22 (SSH only)
- Blocked Ports: 1-100 (comprehensive blocking)
- Security Features:
  * DoS Protection: Enabled
  * IDS/IPS: Enabled
  * Stateful Inspection: Enabled
  * NAT: Disabled

### Use Case:
- Critical infrastructure
- Financial systems
- Sensitive data servers

---

## VMware Attacker Block Template

### Configuration:
- Blocks Specific:
  * IP: 192.168.1.33
  * MAC: 00:0c:29:d9:cb:6a
  * Network: 192.168.1.0/24
- Security Features:
  * High Sensitivity IDS/IPS
  * VMware-specific protections
  * Complete port restrictions

### Use Case:
- Targeted attack response
- VMware-based threats
- Network isolation

---

## How to Apply Templates

### CLI Method:
1. Login as admin
2. Select option 23
3. Choose template
4. Confirm application

### GUI Method:
1. Open Configuration tab
2. Select Templates
3. Choose desired template
4. Click Apply

---

## Testing & Verification

### Automated Tests:
- Basic rules functionality
- NAT operations
- DoS protection
- IDS/IPS systems
- Stateful inspection
- Logging and alerts
- Rule removal
- Configuration persistence

### Manual Verification:
- Port scanning
- Connection testing
- Log analysis
- Alert monitoring

---

## Best Practices

1. Regular template updates
2. Custom template creation
3. Testing before production
4. Regular security audits
5. Log monitoring
6. Template documentation

---

## Questions?

Contact: support@baselfirewall.com
Documentation: docs.baselfirewall.com 