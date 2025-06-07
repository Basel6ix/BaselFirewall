# BaselFirewall Contributing Guide

<div style="text-align: center; margin: 2em 0;">
<h2>B. Abu-Radaha</h2>
<p>Supervisor: M. Nabrawi</p>
<p>Hittien College</p>
<p>May 2025</p>
</div>

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Process](#development-process)
4. [Pull Request Process](#pull-request-process)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Documentation](#documentation)
8. [Security Guidelines](#security-guidelines)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### 1. Fork the Repository
```bash
# Clone your fork
git clone https://github.com/your-username/BaselFirewall.git
cd BaselFirewall

# Add upstream remote
git remote add upstream https://github.com/original/BaselFirewall.git
```

### 2. Set Up Development Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Create a Branch
```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

## Development Process

### 1. Code Organization
```
BaselFirewall/
├── firewall/           # Core firewall functionality
├── cli/               # Command-line interface
├── gui/               # Graphical user interface
├── tests/             # Test suite
├── docs/              # Documentation
└── resources/         # Additional resources
```

### 2. Branch Naming
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `docs/*` - Documentation changes
- `test/*` - Test additions/modifications
- `refactor/*` - Code refactoring

### 3. Commit Messages
```
type(scope): subject

body

footer
```

Example:
```
feat(firewall): add DoS protection module

- Implement SYN flood detection
- Add ICMP flood protection
- Create rate limiting mechanism

Closes #123
```

## Pull Request Process

### 1. Before Submitting
- [ ] Update documentation
- [ ] Add/update tests
- [ ] Run full test suite
- [ ] Check code style
- [ ] Update changelog

### 2. PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing done

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Changelog updated
```

### 3. Review Process
1. Submit PR
2. Address review comments
3. Update based on feedback
4. Get approvals
5. Merge

## Coding Standards

### 1. Python Style Guide
```python
# Follow PEP 8
import os
import sys
from typing import List, Dict

class FirewallRule:
    """Class for managing firewall rules.
    
    Attributes:
        name (str): Rule name
        action (str): Rule action
    """
    
    def __init__(self, name: str, action: str) -> None:
        self.name = name
        self.action = action
    
    def apply_rule(self) -> bool:
        """Apply the firewall rule.
        
        Returns:
            bool: True if successful, False otherwise
        """
        pass
```

### 2. Documentation Style
```python
def block_ip(ip: str, duration: int = None) -> bool:
    """Block an IP address.
    
    Args:
        ip (str): IP address to block
        duration (int, optional): Block duration in seconds
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        ValueError: If IP address is invalid
    """
    pass
```

### 3. Error Handling
```python
try:
    result = some_function()
except SpecificException as e:
    logger.error(f"Specific error: {e}")
    handle_specific_error()
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise
```

## Testing Guidelines

### 1. Test Structure
```python
import unittest

class TestFirewallRules(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.firewall = Firewall()
    
    def test_block_ip(self):
        """Test IP blocking functionality."""
        result = self.firewall.block_ip("192.168.1.1")
        self.assertTrue(result)
        self.assertIn("192.168.1.1", self.firewall.blocked_ips)
    
    def tearDown(self):
        """Clean up after tests."""
        self.firewall.reset()
```

### 2. Running Tests
```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_firewall.py

# Run with coverage
python -m pytest --cov=firewall tests/
```

### 3. Test Coverage
- Aim for 80%+ coverage
- Focus on critical paths
- Include edge cases
- Test error conditions

## Documentation

### 1. Code Documentation
- Use docstrings
- Document classes
- Document functions
- Include examples

### 2. Project Documentation
- README.md
- Installation guide
- User manual
- API documentation
- Architecture overview

### 3. Documentation Updates
- Keep in sync with code
- Include version info
- Add migration guides
- Update examples

## Security Guidelines

### 1. Code Security
- Input validation
- Proper error handling
- Secure defaults
- No hardcoded secrets

### 2. Testing Security
- Security test cases
- Penetration testing
- Vulnerability scanning
- Regular audits

### 3. Reporting Security Issues
- Use private channels
- Include reproduction steps
- Wait for fixes
- Follow disclosure policy 

## How to Contribute

### 1. Reporting Bugs

- Use the GitHub issue tracker
- Include detailed steps to reproduce
- Provide system information
- Include relevant logs
- Describe expected behavior

### 2. Suggesting Features

- Check existing issues first
- Provide clear description
- Explain use case
- Include implementation ideas if possible

### 3. Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Update documentation
6. Submit pull request

## Development Setup

### Prerequisites

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3-pip python3-venv iptables tcpdump

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt
```

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test file
python3 -m pytest tests/test_firewall.py

# Run with coverage
python3 -m pytest --cov=firewall tests/
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings
- Keep functions focused
- Use meaningful names

### Example

```python
from typing import List, Optional

def process_packet(packet: bytes, rules: List[dict]) -> Optional[dict]:
    """
    Process a network packet against firewall rules.

    Args:
        packet: Raw packet data
        rules: List of firewall rules

    Returns:
        dict: Processing result or None if no match
    """
    # Implementation
```

## Documentation

### Writing Documentation

- Use Markdown format
- Include code examples
- Keep it clear and concise
- Update when changing code

### Documentation Structure

```
docs/
├── user/           # User guides
├── technical/      # Technical documentation
├── api/           # API reference
└── examples/      # Code examples
```

## Testing

### Writing Tests

- Use pytest
- Test edge cases
- Mock external dependencies
- Keep tests focused

### Example Test

```python
def test_firewall_rule():
    """Test firewall rule application."""
    rule = {
        "protocol": "tcp",
        "ports": [80],
        "action": "ACCEPT"
    }
    result = apply_rule(rule)
    assert result["status"] == "success"
```

## Security

### Security Guidelines

- Never commit sensitive data
- Follow security best practices
- Report security issues privately
- Keep dependencies updated

### Security Issues

Report security issues to: [Your Security Email]

## Review Process

1. Code review
2. Documentation review
3. Test review
4. Security review
5. Final approval

## Release Process

1. Update version
2. Update changelog
3. Run full test suite
4. Create release tag
5. Build packages
6. Deploy

## Getting Help

- Check documentation
- Search issues
- Join discussions
- Contact maintainers

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.

---

Thank you for contributing to BaselFirewall! 