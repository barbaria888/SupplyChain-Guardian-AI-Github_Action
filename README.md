# Proactive DevSecOps Supply Chain Guardian

[![Supply Chain Guardian](https://img.shields.io/badge/pipeline-supply--chain--guardian-blueviolet)](https://github.com)
[![Security](https://img.shields.io/badge/security-trivy--scanned-brightgreen)](https://github.com/aquasecurity/trivy)
[![AI Patching](https://img.shields.io/badge/AI-Llama%203.2%201B%20%40%20Ollama-orange)](https://ollama.com)

> **Autonomous, closed-loop CVE detection and remediation for containerized workloads — no cloud LLM keys required.**

---

## What This Does

This pipeline detects vulnerabilities in your container images, uses a **local Llama 3.2 1B model** running on the GitHub runner's CPU to generate a patch, validates the fix inside an ephemeral **KinD cluster**, and opens a **pull request with proof** — all automatically.

```
Push → Trivy Scan → CVE Found → Ollama Patches Dockerfile
         → KinD Validates → Re-scan Confirms Fix → PR Opened
```

---

## Architecture

| Layer | Tool | Role |
|---|---|---|
| **Scanning** | Trivy v0.55+ | CVE detection, SBOM generation |
| **AI Reasoning** | Ollama + Llama 3.2 1B | Dockerfile patching, CPU-only |
| **Validation** | KinD v0.23+ | Ephemeral K8s integration test |
| **Orchestration** | GitHub Actions | Full pipeline coordinator |
| **PR Creation** | peter-evans/create-pull-request | Automated, human-reviewable PR |

---

## Repository Structure

```
.
├── agents.md                        # Agent persona definitions
├── .agents/
│   └── skills/
│       └── devsecops_workflow.md    # Domain interaction contract
├── .kind/
│   └── cluster-config.yaml          # KinD 2-node cluster spec
├── .trivy/                           # Trivy policy & ignore files (Phase 3)
├── .github/
│   └── workflows/
│       └── autonomous-patcher.yaml  # The full pipeline (Phase 4)
├── k8s/
│   ├── deployment.yaml              # Production-grade Deployment
│   └── service.yaml                 # ClusterIP Service
├── scripts/
│   └── remediate_cve.py             # AI patching engine (Phase 3)
├── src/
│   ├── main.py                      # FastAPI demo application
│   └── requirements.txt
├── tests/
│   ├── unit/                         # Unit tests (Phase 3)
│   └── integration/                  # Integration tests (Phase 4)
├── Dockerfile                        # ⚠️ Intentionally vulnerable baseline
├── SECURITY.md
└── README.md
```

---

## Agent Personas

See [`agents.md`](./agents.md) for the full definition of:

- **@SecOps** — Trivy scanning and CVE triage
- **@AIPatcher** — Ollama LLM integration and patch generation
- **@SRE** — KinD cluster and Kubernetes manifest validation

---

## Getting Started (Local Development)

### Prerequisites
- Docker Desktop
- `kind` CLI
- `kubectl` CLI
- `trivy` CLI
- `ollama` CLI

### Run the app locally
```bash
docker build -t guardian-demo:latest .
docker run -p 8080:8080 guardian-demo:latest
curl http://localhost:8080/healthz
```

### Run a local scan
```bash
trivy image --format json --output trivy-results.json guardian-demo:latest
```

### Spin up the test cluster
```bash
kind create cluster --config .kind/cluster-config.yaml
kind load docker-image guardian-demo:latest --name guardian-test
kubectl apply -f k8s/
kubectl wait --for=condition=available --timeout=120s deployment/guardian-demo
```

---

## Security Contexts

All Kubernetes manifests enforce:
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `seccompProfile: RuntimeDefault`

---

## Compliance Artifacts

Every pipeline run uploads:
- `trivy-results.json` — original scan
- `patch_audit.log` — full LLM prompt + response
- `kind-test-report.txt` — cluster validation evidence
- `trivy-results-post-patch.json` — remediation proof

Retained for **90 days** for SOC 2 / internal audit purposes.

---

## License

MIT — See [LICENSE](./LICENSE)
