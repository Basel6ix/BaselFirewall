# BaselFirewall Changelog

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

All notable changes to BaselFirewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-03-20

### Added
- Complete firewall disable/enable functionality
- Emergency shutdown feature
- Network topology documentation
- Example configuration files
- Comprehensive logging system

### Changed
- Improved NAT configuration interface
- Enhanced IDS/IPS detection accuracy
- Better DoS protection thresholds
- Updated documentation structure

### Fixed
- NAT interface validation
- Rule persistence after restart
- Configuration file permissions
- Log rotation issues

## [1.0.1] - 2024-02-15

### Added
- Rate limiting for authentication attempts
- Session timeout functionality
- Basic logging system

### Fixed
- User authentication bugs
- Configuration file loading issues
- Permission handling errors

## [1.0.0] - 2025-05-07

### Added
- Initial release of BaselFirewall
- Complete firewall functionality with iptables integration
- IDS/IPS capabilities with real-time packet inspection
- DoS protection with rate limiting
- Stateful inspection
- NAT support
- Command-line interface (CLI)
- Graphical user interface (GUI)
- Comprehensive documentation
- Systemd service integration
- Logging system with rotation
- Configuration management
- User authentication system
- Attack detection and prevention
- Performance monitoring
- Security best practices implementation

### Security
- Default DROP policies
- Rate limiting for ICMP and SSH
- Port scanning detection
- SYN flood protection
- IP blacklisting
- Connection tracking
- Secure configuration management

### Documentation
- Complete user guide
- Technical documentation
- API reference
- Security guidelines
- Installation guide
- Troubleshooting guide
- Performance tuning guide
- Attack testing guide
- Presentation materials
- Q&A preparation guide

### Infrastructure
- Systemd service configuration
- Log rotation setup
- Configuration file structure
- Directory permissions
- Backup and restore functionality
- Version control integration
- License (MIT)
- Git configuration

## [0.9.0] - 2023-12-15

### Added
- Beta release
- Core firewall engine
- Basic rule management
- Configuration file structure
- Testing framework

### Changed
- Improved performance
- Better error handling
- Enhanced documentation

## [0.8.0] - 2023-11-30

### Added
- Alpha release
- Initial codebase
- Basic functionality tests
- Project structure

## [Unreleased]

### Planned Features
- Advanced packet inspection
- Machine learning-based threat detection
- Web-based management interface
- API for external integration
- Container support
- IPv6 support
- VPN integration
- Custom rule scripting
- Real-time analytics dashboard

### Known Issues
- Performance impact with large rule sets
- Memory usage optimization needed
- GUI responsiveness under heavy load
- Limited IPv6 support
- Documentation gaps in advanced features 