# BaselFirewall Rules Templates Guide

This guide explains the various rule templates available in BaselFirewall and how to use them effectively.

## Available Templates

### 1. Web Server Template 🌐

Optimized for web applications and services.

```yaml
template: web_server
ports:
  - 80/tcp  # HTTP
  - 443/tcp # HTTPS
  - 8080/tcp # Alternative HTTP
features:
  - ssl_termination
  - http_inspection
  - xss_protection
  - sql_injection_prevention
```

**Use Cases:**
- Web applications
- REST APIs
- Static websites
- Reverse proxies

### 2. Database Template 💾

Secure configuration for database servers.

```yaml
template: database
ports:
  - 3306/tcp # MySQL
  - 5432/tcp # PostgreSQL
  - 27017/tcp # MongoDB
features:
  - connection_limiting
  - query_filtering
  - access_control
  - data_encryption
```

**Use Cases:**
- MySQL servers
- PostgreSQL instances
- NoSQL databases
- Data warehouses

### 3. Development Template ⚙️

Flexible configuration for development environments.

```yaml
template: development
ports:
  - 3000-4000/tcp # Dev servers
  - 8000-9000/tcp # Test ports
features:
  - debug_logging
  - flexible_access
  - test_endpoints
  - monitoring
```

**Use Cases:**
- Local development
- Testing environments
- CI/CD pipelines
- Debug scenarios

### 4. High Security Template 🛡️

Maximum security for sensitive systems.

```yaml
template: high_security
default_policy: deny
features:
  - strict_access_control
  - deep_packet_inspection
  - anomaly_detection
  - real_time_monitoring
```

**Use Cases:**
- Financial systems
- Healthcare applications
- Government services
- Critical infrastructure

## Core Features

### Deep Inspection 🔍
- Protocol analysis
- Content filtering
- Pattern matching
- Traffic inspection

### DoS Protection 🚫
- Rate limiting
- Connection control
- Traffic throttling
- Resource protection

### IPS Features 🛡️
- Threat detection
- Automatic response
- Real-time protection
- Signature matching

## Security Rules Configuration

### Access Control 🎯
```yaml
access_rules:
  - type: ip_filter
    action: allow
    source: "192.168.1.0/24"
  - type: user_auth
    method: "certificate"
  - type: service
    ports: "80,443"
```

### Time-Based Rules 🕒
```yaml
time_rules:
  - window: "09:00-17:00"
    days: "Mon-Fri"
    action: allow
  - window: "maintenance"
    schedule: "First Sunday"
```

### Geo-Blocking 📍
```yaml
geo_rules:
  allow_countries:
    - US
    - CA
    - UK
  block_regions:
    - high_risk_areas
```

## Monitoring Configuration

### Performance Monitoring 📈
```yaml
monitoring:
  metrics:
    - cpu_usage
    - memory_usage
    - connection_count
    - bandwidth
  thresholds:
    cpu_max: 80%
    mem_max: 75%
```

### Logging System 📝
```yaml
logging:
  level: info
  targets:
    - syslog
    - file
  retention: 30d
  format: json
```

### Alert System ⚠️
```yaml
alerts:
  channels:
    - email
    - slack
    - sms
  triggers:
    - high_cpu
    - connection_spike
    - security_breach
```

## Usage Guide

### Applying Templates

1. Select appropriate template:
   ```bash
   basel template apply web_server --target myapp
   ```

2. Customize configuration:
   ```bash
   basel config edit myapp
   ```

3. Verify rules:
   ```bash
   basel verify myapp
   ```

### Best Practices

1. **Security First**
   - Start with most restrictive template
   - Add permissions as needed
   - Document exceptions
   - Regular security audits

2. **Performance**
   - Monitor resource impact
   - Balance security vs speed
   - Optimize rules regularly
   - Check performance metrics

3. **Management**
   - Keep templates updated
   - Version control changes
   - Document modifications
   - Regular testing

## Template Modification

### Adding Custom Rules
```yaml
custom_rules:
  - name: my_rule
    type: filter
    action: allow
    conditions:
      - protocol: tcp
      - port: 8080
      - source: trusted_networks
```

### Extending Templates
```yaml
template_extension:
  base: web_server
  additional_features:
    - custom_waf
    - api_gateway
  custom_ports:
    - 9000/tcp
```

## Troubleshooting

1. **Common Issues**
   - Rule conflicts
   - Performance impacts
   - Access problems
   - Configuration errors

2. **Debugging**
   ```bash
   basel debug template myapp
   basel logs --level debug
   basel test-rules myapp
   ```

3. **Support**
   - Check documentation
   - Review logs
   - Contact support team
   - Community forums

## Additional Resources

- [Full Documentation](./full_documentation.md)
- [Security Guide](./attack.md)
- [Testing Guide](./attack_testing.md)
- [System Diagrams](./github_diagrams.md) 