# Contributing to Temenos 👾

Thank you for your interest in contributing to Temenos! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Questions and Support](#questions-and-support)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate in communication
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/temenos.git
   cd temenos
   ```
3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/ORIGINAL-OWNER/temenos.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git
- A text editor or IDE of your choice

### Installation

1. **Create a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your environment variables**:
   Create a `.env` file in the project root:
   ```env
   DNSDUMPSTER_API_KEY=your_test_api_key_here
   VIRUSTOTAL_API_KEY=your_test_api_key_here
   ```

4. **Verify the installation**:
   ```bash
   python temenos.py --version
   ```

### Running the Application

```bash
# Basic scan
python temenos.py scan example.com

# With VirusTotal enrichment
python temenos.py scan example.com --virustotal

# Verbose mode for debugging
python temenos.py scan example.com --verbose
```

## Project Structure

```
temenos/
├── temenos.py              # Main CLI application
├── requirements.txt        # Python dependencies
├── setup.sh               # Setup script
├── .env.example           # Environment variable template
├── clients/               # API client modules
│   ├── __init__.py
│   ├── dnsdumpster.py    # DNSDumpster API client
│   └── virustotal.py     # VirusTotal API client
└── utils/                 # Utility modules
    ├── __init__.py
    ├── config.py         # Configuration management
    ├── formatter.py      # Output formatting
    └── logger.py         # Logging utilities
```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug fixes**
- ✨ **New features**
- 📝 **Documentation improvements**
- 🎨 **Code refactoring**
- 🧪 **Tests**
- 🌐 **Translations**
- 💡 **Ideas and suggestions**

### Contribution Workflow

1. **Create a new branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following the coding standards

3. **Test your changes** thoroughly

4. **Commit your changes** with clear, descriptive messages:
   ```bash
   git add .
   git commit -m "Add: Brief description of your changes"
   ```

5. **Keep your fork updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request** on GitHub

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) style guidelines. Key points:

- **Indentation**: Use 4 spaces (no tabs)
- **Line length**: Maximum 88 characters (Black formatter default)
- **Naming conventions**:
  - Functions and variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_CASE`
  - Private methods/variables: `_leading_underscore`

### Code Quality

- **Write docstrings** for all functions, classes, and modules:
  ```python
  def scan_domain(domain: str, enable_vt: bool = False) -> dict:
      """
      Scan a domain using DNSDumpster and optionally VirusTotal.
      
      Args:
          domain: The domain name to scan
          enable_vt: Whether to enable VirusTotal enrichment
          
      Returns:
          Dictionary containing scan results
          
      Raises:
          ValueError: If domain is invalid
      """
      pass
  ```

- **Type hints**: Use type hints for function parameters and return values
- **Error handling**: Always handle exceptions appropriately
- **Logging**: Use the logger utility instead of print statements
- **Comments**: Write clear comments for complex logic

### File Organization

- Keep files focused on a single responsibility
- New API clients should go in the `clients/` directory
- Utility functions should go in the `utils/` directory
- Follow the existing module structure

## Testing Guidelines

### Manual Testing

Before submitting your changes:

1. **Test basic functionality**:
   ```bash
   python temenos.py scan example.com
   ```

2. **Test with different options**:
   ```bash
   python temenos.py scan example.com --virustotal
   python temenos.py scan example.com --format json
   python temenos.py scan example.com --output results.csv
   ```

3. **Test error handling**:
   - Try with invalid domains
   - Try with missing API keys
   - Test rate limit handling

4. **Test on different platforms** (if possible):
   - Linux
   - macOS
   - Windows

### Future: Automated Tests

We plan to implement automated testing. Contributions to add test coverage are highly appreciated!

## Submitting Changes

### Pull Request Guidelines

1. **Update documentation** if needed
2. **Follow the PR template** (if available)
3. **Write a clear PR title**:
   - `Add: New feature description`
   - `Fix: Bug description`
   - `Docs: Documentation update`
   - `Refactor: Code improvement`

4. **Provide a detailed description**:
   - What changes were made
   - Why these changes are necessary
   - Any breaking changes
   - Related issues (if applicable)

5. **Keep PRs focused**: One feature or fix per PR
6. **Be responsive** to review feedback

### Commit Message Format

Use clear, descriptive commit messages:

```
Type: Brief description (50 chars or less)

More detailed explanation if necessary. Wrap at 72 characters.
Explain what and why, not how.

- Bullet points are okay
- Use present tense: "Add feature" not "Added feature"
```

**Types**: `Add`, `Fix`, `Update`, `Remove`, `Refactor`, `Docs`, `Test`

### Review Process

1. A maintainer will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged
4. Your contribution will be credited in the release notes

## Reporting Bugs

### Before Submitting a Bug Report

- Check the existing issues to avoid duplicates
- Verify that you're using the latest version
- Try to reproduce the issue consistently

### How to Submit a Bug Report

Create an issue with the following information:

**Title**: Brief, descriptive summary

**Environment**:
- OS: [e.g., Ubuntu 22.04, macOS 14, Windows 11]
- Python version: [e.g., 3.11.5]
- Temenos version: [e.g., 1.0.0]

**Description**:
- What you expected to happen
- What actually happened
- Steps to reproduce the issue

**Logs/Screenshots**:
- Include relevant error messages
- Use code blocks for logs
- Attach screenshots if applicable

**Example**:
```
## Bug Report

### Environment
- OS: Ubuntu 22.04
- Python: 3.11.5
- Temenos: 1.0.0

### Description
When scanning a domain with VirusTotal enabled, the application crashes with a timeout error.

### Steps to Reproduce
1. Run `python temenos.py scan example.com --virustotal`
2. Wait for DNSDumpster results
3. Application crashes during VT enrichment

### Error Message
```
TimeoutError: VirusTotal API request timed out after 30 seconds
```

### Expected Behavior
The application should handle timeouts gracefully and continue with the scan.
```

## Feature Requests

We welcome feature suggestions! When submitting a feature request:

1. **Check existing issues** to avoid duplicates
2. **Clearly describe the feature** and its use case
3. **Explain why** this feature would be useful
4. **Provide examples** if possible

## Questions and Support

- **General questions**: Open a discussion on GitHub
- **Security issues**: Email the maintainers directly (do not open public issues)
- **Documentation**: Check the README.md and QUICKSTART.md first

## Development Tips

### Debugging

Enable verbose logging:
```bash
python temenos.py scan example.com --verbose
```

### Working with APIs

- Use the free tier for development
- Be mindful of rate limits
- Test with small datasets first
- Handle API errors gracefully

### Code Review Checklist

Before submitting your PR, review:

- [ ] Code follows PEP 8 style guidelines
- [ ] All functions have docstrings
- [ ] Type hints are used
- [ ] Error handling is implemented
- [ ] No hardcoded credentials or API keys
- [ ] Logging instead of print statements
- [ ] Documentation is updated
- [ ] Code works on Linux, macOS, and Windows (if possible)
- [ ] No unnecessary dependencies added

## Recognition

All contributors will be recognized in:
- The project's README.md
- Release notes
- Git commit history

Thank you for contributing to Temenos! 🎉

---

*This document is a living guide and may be updated as the project evolves.*
