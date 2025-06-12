# BaselFirewall System Diagrams

This document provides detailed explanations of the BaselFirewall system architecture and workflows through four key diagrams.

## Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Security Workflow Guide](#security-workflow-guide)
3. [Template Management Guide](#template-management-guide)
4. [Attack Response System Guide](#attack-response-system-guide)

## System Architecture Overview

This diagram illustrates the complete structure of BaselFirewall, organized in layers:

### Frontend Layer (🖥️)
- **GUI Dashboard**: Web-based interface for visual management
- **CLI Tools**: Command-line interface for scripting and automation
- **API Gateway**: Integration point for external services

### Authentication Layer (🔐)
- **Auth Service**: Handles user authentication and session management
- **Role Manager**: Controls access permissions and user roles

### Core Services (⚙️)
- **Core Engine**: Main processing unit for firewall operations
- **Rule Manager**: Handles firewall rules and policy enforcement
- **Config System**: Manages system settings and profiles

### Security Layer (🛡️)
- **IDS/IPS**: Intrusion detection and prevention
- **Firewall Core**: Main packet filtering and NAT operations
- **DoS Protection**: Prevents denial of service attacks

### Network Layer (🌐)
- **Network Stack**: Handles network interface operations
- **Packet Process**: Performs deep packet inspection

### Monitoring (📊)
- **Logger**: Tracks system events and activities
- **Alert System**: Manages notifications and reporting

#### Usage:
1. Use this diagram when explaining the system's overall architecture
2. Reference it during deployment planning
3. Helpful for understanding component interactions
4. Essential for troubleshooting system issues

---

## Security Workflow Guide

This diagram shows the step-by-step process of packet handling and security decisions:

### Traffic Processing (📥)
- **Incoming Traffic**: Initial entry point
- **Initial Scan**: First-level packet analysis
- **State Check**: Connection state verification

### Security Analysis (🔍)
- **Threat Detection**: Identifies potential security threats
- **Risk Assessment**: Evaluates threat severity
- **Policy Validation**: Checks against security policies

### Action Layer (🎯)
- **Decision Engine**: Determines packet fate
- **Accept/Drop/Alert**: Possible actions for each packet

### Monitoring (📝)
- **Logging**: Records all actions
- **Reports**: Generates analysis reports
- **Notifications**: Sends alerts to administrators

#### Usage:
1. Use for training new system administrators
2. Reference during security incident response
3. Helpful for understanding packet flow
4. Essential for debugging security issues

---

## Template Management Guide

This diagram shows the template system and its features:

### Template Profiles (🎨)
- **Web Server**: HTTP/HTTPS configurations
- **Database**: Database server protection
- **Development**: Development environment settings
- **High Security**: Maximum security configuration

### Features (⚡)
- **Deep Inspection**: Protocol and content analysis
- **DoS Protection**: Rate limiting and connection control
- **IPS Features**: Threat detection and response

### Security Rules (🔒)
- **Access Control**: IP and user authentication
- **Time-Based**: Scheduled access rules
- **Geo-Blocking**: Geographic access control

### Monitoring (📊)
- **Performance**: Resource and throughput monitoring
- **Logging**: Event and audit tracking
- **Alerts**: Notification system

#### Usage:
1. Reference when configuring new servers
2. Guide for selecting appropriate templates
3. Understanding available security features
4. Planning security implementations

---

## Attack Response System Guide

This diagram illustrates the attack detection and response system:

### Threat Detection (🔍)
- **Monitor**: Continuous traffic analysis
- **Identify**: Threat classification
- **Evaluate**: Impact assessment

### Attack Types (⚔️)
- **DoS/DDoS**: Flood and resource exhaustion attacks
- **Port Scan**: Unauthorized port probing
- **Malware**: Malicious software detection
- **Web Attacks**: Web-based vulnerabilities

### Response Actions (🛡️)
- **Block**: IP banning and port closure
- **Rate Limit**: Traffic control measures
- **Isolate**: Network segmentation

### Alert System (📢)
- **Notify**: Administrator alerts
- **Report**: Incident documentation
- **Update**: Rule and policy updates

#### Usage:
1. Reference during security incidents
2. Training for incident response teams
3. Planning security measures
4. Developing response procedures

---

## Viewing the Diagrams

The actual diagrams can be viewed in two ways:

1. **HTML View**: Open `diagrams.html` in any web browser for an interactive view
2. **Documentation**: Visit our [documentation site](https://baselfirewall.readthedocs.io) for the full documentation including these diagrams

## Contributing

To modify these diagrams:

1. Edit the Mermaid source code in `diagrams.html`
2. Use the [Mermaid Live Editor](https://mermaid.live) for testing changes
3. Submit a pull request with your modifications

## Additional Resources

- [Mermaid.js Documentation](https://mermaid.js.org/intro/)
- [BaselFirewall Documentation](./full_documentation.md)
- [Attack Response Guide](./attack.md)
- [Testing Guide](./attack_testing.md) 