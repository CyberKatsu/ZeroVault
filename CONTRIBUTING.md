# Contributing to ZeroVault

Thank you for your interest in contributing to ZeroVault! This document provides guidelines and information for contributors.

## Development Setup

See the [README.md](README.md) for detailed setup instructions.

## Code Style

- Follow PEP 8 for Python code
- Use type hints where possible
- Write docstrings for all public functions and classes
- Keep cryptographic code well-commented with security justifications

## Testing

- All new features must include comprehensive tests
- Run `pytest` before submitting PRs
- Maintain or improve test coverage

## Security

- Never commit secrets or sensitive data
- Be mindful of security implications when making changes
- Review the [SECURITY.md](SECURITY.md) and [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) documents

## Pull Requests

- Use descriptive commit messages
- Reference any related issues
- Ensure CI passes before requesting review
- Keep PRs focused on a single feature or fix

## Reporting Security Issues

Please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.