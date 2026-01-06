# Healthcare EHR Security Lab (FastAPI) — RBAC, Audit Logging, Threat Detection

Security-focused backend lab simulating core controls used in Electronic Health Record (EHR) systems. Implements authentication, Role-Based Access Control (RBAC), HIPAA-style audit logging, and real-time detection for insider misuse and external brute-force attempts (IP-based).

**Keywords (ATS):** SOC, SIEM, HIPAA, NIST 800-53, RBAC, IAM, JWT, Audit Logging, Incident Response, Threat Detection, FastAPI, Python, Security Monitoring, Brute Force, Insider Threat, Least Privilege, Access Control, Security Controls, Compliance.

---

## What This Demonstrates

- **Access Control (RBAC / Least Privilege):** role-to-permission enforcement for protected resources
- **Authentication:** JWT token issuance and validation
- **Audit Controls:** structured JSON logs for login attempts and patient access attempts (allowed/denied)
- **Security Monitoring:** real-time log watcher generating alerts for:
  - **Insider threat:** repeated unauthorized patient record access
  - **External threat:** IP-based brute-force login attempts
- **Incident Response:** documented detection logic and investigation-ready event trails

---

## Control Alignment (HIPAA + NIST)

- HIPAA 45 CFR §164.312(a)(1) Access Control
- HIPAA 45 CFR §164.312(b) Audit Controls
- HIPAA 45 CFR §164.308(a)(5)(ii)(C) Log-in Monitoring
- NIST SP 800-53: AC-3, AC-6, AU-2, AU-3, AU-6, IR-4, SI-4

---

## Assumptions & Limitations

- **Synthetic data only** (no real PHI / ePHI)
- **Secrets externalized** via environment variables (no secrets committed)
- Logs excluded from version control
- No encryption-at-rest, no SIEM integration, no enterprise IAM/SSO (out of scope for this lab)

---

## Run Locally

```powershell
python -m venv venv
venv\Scripts\Activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
python app/watch_audit.py
