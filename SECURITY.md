# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

Cerberus is a security tool. We take vulnerabilities in our own code seriously.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities by emailing: **security@sixsenseenterprise.com**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix**: Within 30 days for confirmed vulnerabilities

### Scope

The following are in scope:
- Bypass of any detection layer (L1-L4)
- False negative in the correlation engine
- Data leakage from the platform itself
- Dependency vulnerabilities that affect Cerberus functionality

### Recognition

We maintain a security hall of fame for responsible disclosures. Contributors will be credited in release notes unless they prefer to remain anonymous.

## Security Design Principles

Cerberus is built on the principle that **you cannot build a detector without first being the attacker**. The attack harness (Phase 1) exists solely for defensive research purposes. All attack tooling is clearly labeled and separated from the detection platform.
