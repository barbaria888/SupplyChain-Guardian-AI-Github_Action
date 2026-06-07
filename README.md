# Supply Chain Guardian AI

[![Autonomous Supply Chain Patcher](https://github.com/barbaria888/SupplyChain-Guardian-AI/actions/workflows/autonomous-patcher.yaml/badge.svg)](https://github.com/barbaria888/SupplyChain-Guardian-AI/actions/workflows/autonomous-patcher.yaml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Supply%20Chain%20Guardian%20AI-blueviolet?logo=github)](https://github.com/marketplace/actions/supply-chain-guardian-ai)
[![Supply Chain Guardian](https://img.shields.io/badge/pipeline-supply--chain--guardian-blueviolet)](https://github.com)
[![Security](https://img.shields.io/badge/security-trivy--scanned-brightgreen)](https://github.com/aquasecurity/trivy)
[![AI Patching](https://img.shields.io/badge/AI-Multi--Provider-orange)](https://ollama.com)

> **Autonomous, closed-loop CVE detection and remediation for containerized workloads — local CPU inference, cloud LLMs, or bring your own.**

<img width="1024" height="1024" alt="overview" src="https://github.com/user-attachments/assets/4a78c1c1-203d-48c9-b176-ccbf505009d8" />

---

## What This Does

This GitHub Action detects vulnerabilities in your container images, uses an **AI model** to generate a Dockerfile patch, validates the fix inside an ephemeral **KinD cluster**, and opens a **pull request with proof** — all automatically.

<!-- Premium Liquid Glass Gradient -->

<p align="center">
  <a href="https://www.youtube.com/watch?v=9zQBe_HQFak">
    <img
      src="https://capsule-render.vercel.app/api?type=rounded&height=150&text=Watch%20Pipeline%20Walkthrough%20on%20Youtube▶︎&fontSize=44&fontAlignY=43&fontColor=FFFFFF&animation=fadeIn&desc=AI-Powered%20Container%20Security%20Architecture&descAlignY=69&descSize=17&color=0:F8FAFC,10:E0F2FE,24:BAE6FD,40:93C5FD,58:A5B4FC,74:C4B5FD,88:FDE68A,100:FBCFE8"
      style="
        border-radius:32px;
        box-shadow:
          0 10px 40px rgba(148,163,184,0.18),
          inset 0 1px 1px rgba(255,255,255,0.55),
          inset 0 -1px 1px rgba(255,255,255,0.20);
        border:1px solid rgba(255,255,255,0.32);
      "
    />
  </a>
</p>



```
Push → Trivy Scan → CVE Found → AI Patches Dockerfile
         → Smoke Test → KinD Validates → Re-scan Confirms → PR Opened
```

**Zero data egress** with local Ollama (default), or use Gemini / OpenAI for faster inference.

---

## ⚡ Quickstart



```yaml
name: Supply Chain Guardian
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Nightly CVE check

permissions:
  contents: write
  pull-requests: write

jobs:
  guardian:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Supply Chain Guardian
        uses: barbaria888/SupplyChain-Guardian-AI@v1
        with:
          dockerfile: './Dockerfile'
```

That's it. The action handles everything — scanning, patching, validation, and PR creation.

---

## 🤖 Multi-Provider LLM Support

Choose the inference engine that fits your needs:

### Option 1: NVIDIA Nemotron via API Key (Recommended Cloud Setup)

Create this repository secret first in **GitHub Settings → Secrets and variables → Actions**: `NVIDIA_NIM_API_KEY` (get your key from NVIDIA API Catalog: https://build.nvidia.com/).

```yaml
- uses: barbaria888/SupplyChain-Guardian-AI@v1
  with:
    provider: 'openai'
    model: 'nvidia/nemotron-3-ultra-550b-a55b'
    openai-endpoint: 'https://integrate.api.nvidia.com/v1/chat/completions'
    api-key: ${{ secrets.NVIDIA_NIM_API_KEY }}
```

### Option 2: Local Ollama (Zero Cost, Full Privacy)

```yaml
- uses: barbaria888/SupplyChain-Guardian-AI@v1
  with:
    provider: 'ollama'
    model: 'llama3.2:1b'    # ~700MB, runs on GitHub runner CPU
```

### Option 3: Google Gemini (Fast, Low Cost)

```yaml
- uses: barbaria888/SupplyChain-Guardian-AI@v1
  with:
    provider: 'gemini'
    model: 'gemini-2.0-flash'
    api-key: ${{ secrets.GEMINI_API_KEY }}
```

### Option 4: OpenAI / Azure OpenAI

```yaml
- uses: barbaria888/SupplyChain-Guardian-AI@v1
  with:
    provider: 'openai'
    model: 'gpt-4o-mini'
    api-key: ${{ secrets.OPENAI_API_KEY }}
```

---

## Architecture

<img width="1536" height="1024" alt="Architecture" src="https://github.com/user-attachments/assets/5298fd37-a5f7-47ae-b68b-e66837630612" />

| Layer | Tool | Role |
|---|---|---|
| **Scanning** | Trivy | CVE detection, SBOM generation |
| **AI Reasoning** | Ollama / Gemini / OpenAI | Dockerfile patching |
| **Validation** | KinD | Ephemeral K8s integration test |
| **Orchestration** | GitHub Actions | Full pipeline coordinator |
| **PR Creation** | peter-evans/create-pull-request | Automated, human-reviewable PR |

---

## 📋 Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `dockerfile` | No | `Dockerfile` | Path to the Dockerfile to scan and patch |
| `image-ref` | No | `''` | Pre-built image to scan (skips build step) |
| `severity` | No | `CRITICAL,HIGH` | Trivy severity filter |
| `provider` | No | `ollama` | LLM provider: `ollama`, `gemini`, `openai` |
| `model` | No | *(auto)* | Model name for the selected provider |
| `api-key` | No | `''` | API key for cloud providers |
| `openai-endpoint` | No | `https://api.openai.com/v1/chat/completions` | OpenAI-compatible endpoint (set NVIDIA NIM URL for Nemotron) |
| `trivy-version` | No | `0.55.0` | Trivy version |
| `kind-enabled` | No | `true` | Enable KinD cluster validation |
| `kind-config` | No | `.kind/cluster-config.yaml` | KinD cluster config path |
| `k8s-manifests` | No | `k8s/` | K8s manifests directory |
| `create-pr` | No | `true` | Auto-create Pull Request |
| `pr-branch` | No | `auto-patcher/cve-remediation` | Branch name for the PR |
| `pr-labels` | No | `security,automated-patch,...` | PR labels |
| `fail-on-vulnerability` | No | `true` | Fail if CVEs can't be patched |
| `ollama-timeout` | No | `120` | LLM inference timeout (seconds) |

## 📤 Outputs

| Output | Description |
|---|---|
| `vulnerabilities-found` | Whether CRITICAL/HIGH CVEs were detected |
| `patch-applied` | Whether the AI generated a valid patch |
| `smoke-test-passed` | Whether the patched Dockerfile compiled |
| `kind-validation-passed` | Whether KinD deployment succeeded |
| `pr-url` | URL of the created Pull Request |
| `trivy-results-path` | Path to scan results JSON |
| `audit-log-path` | Path to the LLM audit log |

---

## 🛡️ Security Design

### Hallucination Defense (3-Layer)

1. **Instruction Whitelist** — Every Dockerfile line must start with a valid instruction (`FROM`, `RUN`, `COPY`, etc.). Invented keywords like `CREATEGROUP` or `ADDuser` are rejected instantly.
2. **Docker Build Smoke Test** — The patched Dockerfile must compile with `docker build` before any artifact is uploaded.
3. **KinD Cluster Validation** — The patched image must boot, pass health probes, and show zero `CrashLoopBackOff` pods.

### Side-by-Side Patching

The AI writes to `Dockerfile.patched` — the original file is **never touched** until the smoke test passes. If the patch is rejected, the broken file is uploaded to a `rejected-patch-forensic` artifact for audit.

### Security Contexts

All Kubernetes manifests enforce:
- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `seccompProfile: RuntimeDefault`

---

## 📊 Compliance Artifacts

Every pipeline run uploads (90-day retention):

| Artifact | Purpose |
|---|---|
| `trivy-results.json` | Original vulnerability report |
| `patch_audit.log` | Full LLM prompt + response for audit review |
| `kind-test-report.txt` | KinD cluster validation evidence |
| `trivy-results-post-patch.json` | Proof of CVE remediation |

---

## 🏗️ Repository Structure

```
.
├── action.yml                        # GitHub Marketplace Action definition
├── agents.md                         # Agent persona definitions
├── .agents/skills/                   # Domain interaction contracts
├── .kind/cluster-config.yaml         # KinD 2-node cluster spec
├── .trivy/                           # Trivy policy & ignore files
├── .github/workflows/                # Internal pipeline (dogfooding)
├── k8s/                              # Production-grade K8s manifests
├── scripts/remediate_cve.py          # AI patching engine (multi-provider)
├── src/                              # Demo FastAPI application
├── tests/unit/                       # 43 unit tests
├── tests/integration/                # KinD integration test script
├── Dockerfile                        # Intentionally vulnerable baseline
├── SECURITY.md                       # Responsible disclosure policy
└── README.md
```

---

## 🧑‍💻 Local Development

```bash
# Build and scan locally
docker build -t guardian-demo:latest .
trivy image --format json --output trivy-results.json guardian-demo:latest

# Run the AI patcher locally with NVIDIA Nemotron
PROVIDER=openai \
API_KEY="<NVIDIA_NIM_API_KEY>" \
OPENAI_MODEL="nvidia/nemotron-3-ultra-550b-a55b" \
OPENAI_ENDPOINT="https://integrate.api.nvidia.com/v1/chat/completions" \
python scripts/remediate_cve.py

# Validate in a local KinD cluster
kind create cluster --config .kind/cluster-config.yaml
kind load docker-image guardian-demo:latest --name guardian-test
kubectl apply -f k8s/
kubectl wait --for=condition=available --timeout=120s deployment/guardian-demo
```

---

## License

MIT — See [LICENSE](./LICENSE)


> **Autonomous, closed-loop CVE detection and remediation for containerized workloads — supports NVIDIA Nemotron API keys out of the box.**
