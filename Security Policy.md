# Security Policy

## Supported Scope

This repository is a **security-focused demonstration project** intended for educational and portfolio purposes only.

The system simulates core healthcare security controls using **synthetic data** and does **not** process real patient information (PHI/ePHI).

---

## Data Handling & Privacy

- All user accounts and patient records are **synthetic**
- No real identifiers, addresses, dates of birth, or medical data are used
- Runtime audit logs are excluded from version control
- Secrets are externalized via environment variables and never committed

Submitting real PHI or sensitive personal data to this repository is **strictly prohibited**.

---

## Reporting Security Issues

If you identify a security concern related to:
- Authentication logic
- Access control enforcement
- Audit logging integrity
- Threat detection logic
- Repository configuration

Please **do not open a public issue**.

Instead, report responsibly by contacting:

**Maintainer:** Brian Wallace  
**Contact:** GitHub direct message or private communication

Include:
- A clear description of the issue
- Steps to reproduce (if applicable)
- Any relevant logs or screenshots (sanitized)

---

## Out of Scope

The following are considered **out of scope** for this project:

- Production deployment security
- Encryption at rest
- Enterprise IAM / SSO integration
- Network-layer security controls (firewalls, IDS/IPS)
- Centralized SIEM integration
- Vulnerabilities related to synthetic demo credentials

---

## Responsible Use

This project is intended to demonstrate **security control patterns**, not to operate as a production Electronic Health Record (EHR) system.

Use of this repository implies acknowledgment of its educational scope and limitations.

---

## Disclosure Philosophy

Security findings are welcomed when responsibly reported. This project values clarity, transparency, and ethical security research practices.
