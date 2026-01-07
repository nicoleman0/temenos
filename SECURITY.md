
# Security Policy

## Supported Versions

Temenos is currently in its initial release phase. Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Temenos seriously. If you discover a security vulnerability, please follow these guidelines:

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities. Instead:

1. **Email**: Send details to the project maintainer via GitHub
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)
   - Your contact information for follow-up

### What to Expect

- **Initial Response**: You will receive an acknowledgment within 48 hours
- **Updates**: Progress updates will be provided every 5-7 days
- **Timeline**: We aim to address critical vulnerabilities within 30 days
- **Disclosure**: Once fixed, coordinated disclosure will be arranged with you
- **Credit**: Security researchers will be credited (unless anonymity is preferred)

### Scope

Security issues relevant to Temenos include:

- Command injection vulnerabilities
- API key exposure or leakage
- Improper input validation
- Dependency vulnerabilities in requirements.txt
- Code execution vulnerabilities

### Out of Scope

- Issues in third-party APIs (DNSDumpster, VirusTotal)
- Social engineering attacks
- Physical security issues
- Denial of Service (DoS) attacks against local CLI tool

Thank you for helping keep Temenos and its users safe!
