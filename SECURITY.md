# Security Policy

## Reporting a Vulnerability

This repository is an automated security pipeline.
Vulnerabilities in the **pipeline itself** (e.g., a prompt injection in
the Ollama remediation script, or an RBAC bypass in the KinD manifests)
should be reported privately.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

### Contact

Email: `arorahardik0811@gmail.com`  
Response SLA: 48 hours for acknowledgement, 7 days for initial triage.

### Scope

| In Scope | Out of Scope |
|---|---|
| `scripts/remediate_cve.py` prompt injection | The Ollama upstream binary |
| GitHub Actions OIDC token exposure | GitHub Actions platform bugs |
| RBAC in `k8s/` manifests | KinD upstream bugs |
| Secrets hardcoded in any committed file | Third-party action CVEs |

### Process

1. You email us with a description and reproduction steps.
2. We confirm the vulnerability within 48 hours.
3. We issue a fix and credit you (if desired) in the release notes.
4. We publish a public advisory after the fix is merged.

## Automated Security

This repository uses its own pipeline to keep itself secure:
- All base images are scanned on every push via Trivy.
- Dependency trees are audited on every PR via `pip-audit`.
- SAST is run via CodeQL on every push to `main`.
