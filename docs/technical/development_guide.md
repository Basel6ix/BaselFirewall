# BaselFirewall Development Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents

## Overview
This guide provides detailed information for developers working on BaselFirewall, including setup, architecture, coding standards, and contribution guidelines.

## Development Environment Setup

### Prerequisites
- Python 3.8 or higher
- iptables
- Git
- Virtual environment (recommended)

### Setup Steps
```bash
# Clone the repository
git clone https://github.com/Basel6ix/BaselFirewall.git
cd BaselFirewall

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

## Project Structure
```
BaselFirewall/
├── firewall/           # Core firewall implementation
├── gui/               # GUI implementation
├── tests/             # Test suite
├── docs/              # Documentation
├── scripts/           # Utility scripts
└── config/            # Configuration files
```

## Coding Standards

### Python Style Guide
- Follow PEP 8 guidelines
- Use type hints
- Document all functions and classes
- Maximum line length: 88 characters
- Use black for code formatting

### Code Organization
- One class per file
- Clear separation of concerns
- Use dependency injection
- Follow SOLID principles

## Testing

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_rules.py

# Run with coverage
pytest --cov=firewall tests/
```

### Writing Tests
- Use pytest fixtures
- Mock external dependencies
- Test edge cases
- Maintain high coverage

## Debugging

### Logging
```python
from firewall.logging import log_event

# Log levels
log_event("Debug message", "DEBUG")
log_event("Info message", "INFO")
log_event("Warning message", "WARNING")
log_event("Error message", "ERROR")
```

### Debug Mode
```bash
# Run in debug mode
python main.py --debug

# Enable verbose logging
python main.py --verbose
```

## Performance Considerations

### Optimization Guidelines
- Use connection tracking
- Implement rate limiting
- Cache frequently accessed data
- Use efficient data structures

### Profiling
```bash
# Run with profiling
python -m cProfile main.py

# Memory profiling
python -m memory_profiler main.py
```

## Security Best Practices

### Code Security
- Validate all inputs
- Sanitize user data
- Use secure defaults
- Implement proper error handling

### Testing Security
- Run security scans
- Test for vulnerabilities
- Check for common exploits
- Validate configurations

## Contributing

### Workflow
1. Create feature branch
2. Write tests
3. Implement feature
4. Run tests
5. Submit pull request

### Pull Request Process
- Update documentation
- Add test coverage
- Follow style guide
- Get code review

## Release Process

### Versioning
- Follow semantic versioning
- Update CHANGELOG.md
- Tag releases
- Update documentation

### Deployment
```bash
# Build package
python setup.py sdist bdist_wheel

# Upload to PyPI
twine upload dist/*
```

## Troubleshooting

### Common Issues
1. Permission errors
   - Check sudo access
   - Verify iptables permissions

2. Service issues
   - Check systemd logs
   - Verify configuration

3. Performance problems
   - Monitor system resources
   - Check rule complexity

### Debug Tools
- tcpdump
- iptables -L -v -n
- systemctl status
- journalctl

## Additional Resources

### Documentation
- [API Reference](api_reference.md)
- [Architecture Guide](architecture.md)
- [Security Guide](security.md)

### External Links
- [Python Documentation](https://docs.python.org)
- [iptables Manual](https://linux.die.net/man/8/iptables)
- [Security Best Practices](https://owasp.org) 