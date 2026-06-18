# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v2.x | ✅ Actively maintained |
| v1.x | ⚠️ Security fixes only |

## Reporting a Vulnerability

This repository is an automated security pipeline.
Vulnerabilities in the **pipeline itself** (e.g., a prompt injection in
the AI remediation script, or an RBAC bypass in the KinD manifests)
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
| `enforce-non-root` bypass via crafted Dockerfile | LLM model weight vulnerabilities |
| Dynamic build context path traversal | OpenAI/NVIDIA API platform bugs |
| Smoke test env injection (`MONGO_URI` / `DATABASE_URL`) abuse | Docker daemon vulnerabilities |
| API key leakage in `patch_audit.log` | Trivy false-positive scan results |

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
- AI-generated patches are validated through a 5-gate pipeline:
  1. Instruction whitelist (hallucination defense)
  2. Adaptive blueprint integrity gate
  3. Docker build smoke test
  4. Runtime stability check with health probe
  5. KinD cluster integration test

## Security Design Principles (v2)

- **Manifest-First Remediation**: AI fixes OS packages via `apk`/`apt` pins; never injects inline `npm install` commands.
- **Side-by-Side Patching**: Original `Dockerfile` is never touched until all gates pass.
- **Configurable Non-Root Policy**: The `enforce-non-root` input controls whether `USER` instruction is mandatory.
- **Smoke Test Isolation**: Dummy database URIs are injected to prevent runtime crashes without exposing real credentials.
- **API Key Fallback**: `api-key` input falls back to `env.API_KEY` — secrets never hardcoded.
