# Supply Chain Guardian AI

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Supply%20Chain%20Guardian%20AI-blueviolet?logo=github)](https://github.com/marketplace/actions/supply-chain-guardian-ai)
[![Autonomous Supply Chain Patcher](https://github.com/barbaria888/SupplyChain-Guardian-AI-Github_Action/actions/workflows/autonomous-patcher.yaml/badge.svg)](https://github.com/barbaria888/SupplyChain-Guardian-AI-Github_Action/actions/workflows/autonomous-patcher.yaml)
[![Security](https://img.shields.io/badge/security-trivy--scanned-brightgreen?logo=aquasecurity)](https://github.com/aquasecurity/trivy)
[![AI Patching](https://img.shields.io/badge/AI-Multi--Provider-orange)](https://ollama.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Autonomous, closed-loop CVE detection and remediation for containerized workloads — local CPU inference, cloud LLMs, or bring your own API key.**

---

## 💡 What is Supply Chain Guardian AI?
<img src="https://hardik0811arora.hashnode.dev/_next/image?url=https%3A%2F%2Fcdn.hashnode.com%2Fuploads%2Fcovers%2F63cfb22ea39405dcc990b569%2Fdabe9265-ded4-4b24-b783-619f4d817243.png&w=3840&q=75">




<table>
<tr>

<td width="50%" valign="top">

###  SupplyChain Guardian AI Explainer

<p align="center">
<a href="https://www.youtube.com/watch?v=9zQBe_HQFak">
<img width="220" alt="SupplyChain Guardian AI Demo" src="https://github.com/user-attachments/assets/0b34021a-cec5-46bb-9b42-d1737dc36315"/>
</a>
</p>

Watch the complete explainer covering:

- Kubernetes DevSecOps Workflow
- End-to-End Platform Walkthrough

</td>

<td width="50%" valign="top">

### ✍️ Building a Zero-Egress AI DevSecOps Pipeline

<p align="center">
<a href="https://hardik0811arora.hashnode.dev/building-a-zero-egress-ai-driven-devsecops-pipeline-my-journey-with-supplychain-guardian-ai?utm_source=hashnode&utm_medium=feed">
<img src="https://img.shields.io/badge/Read_on-Hashnode-2962FF?style=for-the-badge&logo=hashnode&logoColor=white"/>
</a>
</p>

Read about:

- Lessons from Building SupplyChain Guardian AI

</td>

</tr>
</table>

**Supply Chain Guardian AI** is an all-in-one GitHub Action that automatically secures your containerized applications:
1. 🔍 **Scans** your container images using [Trivy](https://github.com/aquasecurity/trivy) for `CRITICAL` and `HIGH` vulnerabilities.
2. 🤖 **Patches** vulnerable Dockerfiles using AI (Local Ollama, NVIDIA NIM, OpenAI, or DeepSeek).
3. 🧪 **Smoke Tests** the patched Dockerfile (`docker build` + runtime health check).
4. ☸️ **Validates** deployment stability inside a temporary [KinD (Kubernetes in Docker)](https://kind.sigs.k8s.io/) cluster *(optional)*.
5. 🔀 **Opens a Pull Request** with complete proof and security audit logs.

```
Push / Cron → Trivy Scan → CVE Found → AI Patches Dockerfile
       → Smoke Test → KinD Validates → Re-scan Confirms → PR Opened
```

---

## 📌 Table of Contents
- [⚡ Quickstart](#-quickstart)
- [📖 Common Workflow Examples](#-common-workflow-examples)
  - [1. Minimal Setup (Default Local Ollama)](#1-minimal-setup-default-local-ollama)
  - [2. Recommended Cloud Setup (NVIDIA NIM / DeepSeek / Kimi)](#2-recommended-cloud-setup-nvidia-nim--deepseek--kimi)
  - [3. Scanning a Specific Dockerfile in a Monorepo](#3-scanning-a-specific-dockerfile-in-a-monorepo)
  - [4. Simple App without Kubernetes (KinD Disabled)](#4-simple-app-without-kubernetes-kind-disabled)
  - [5. Full Production Setup (KinD Testing + Auto PR)](#5-full-production-setup-kind-testing--auto-pr)
- [🤖 Supported AI Providers](#-supported-ai-providers)
- [📋 Complete Inputs & Outputs](#-complete-inputs--outputs)
- [🛡️ Security & Reliability Features](#️-security--reliability-features)
- [❓ FAQ & Troubleshooting](#-faq--troubleshooting)
- [📄 License](#license)

---

## ⚡ Quickstart

Add this step to your GitHub Actions workflow file (e.g. `.github/workflows/security.yml`):

```yaml
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: write
  pull-requests: write

jobs:
  scan-and-remediate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Supply Chain Guardian
        uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
        with:
          dockerfile: './Dockerfile'
```

---

## 📖 Common Workflow Examples

### 1. Minimal Setup (Default Local Ollama)
No API key required! Uses Ollama (`llama3.2:1b`) directly on the GitHub Actions runner CPU.

```yaml
- name: Run Supply Chain Guardian (Local AI)
  uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
  with:
    dockerfile: './Dockerfile'
```

---

### 2. Recommended Cloud Setup (NVIDIA NIM / DeepSeek / Kimi)
Fast, high-accuracy inference using cloud AI models.

> **Prerequisite:** Add `NVIDIA_NIM_API_KEY` (or your provider's API key) to your **Repository Settings → Secrets and variables → Actions**.

```yaml
- name: Run Supply Chain Guardian (NVIDIA NIM)
  uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
  with:
    dockerfile: './Dockerfile'
    provider: 'openai'
    model: 'moonshotai/kimi-k2.6'  # or 'deepseek-ai/deepseek-v4-flash'
    openai-endpoint: 'https://integrate.api.nvidia.com/v1'
    api-key: ${{ secrets.NVIDIA_NIM_API_KEY }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### 3. Scanning a Specific Dockerfile in a Monorepo
Specify sub-directory paths easily:

```yaml
- name: Run Supply Chain Guardian (Backend App)
  uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
  with:
    dockerfile: './backend/Dockerfile'
    provider: 'openai'
    model: 'z-ai/glm-5.2'
    openai-endpoint: 'https://integrate.api.nvidia.com/v1'
    api-key: ${{ secrets.NVIDIA_NIM_API_KEY }}
```

---

### 4. Simple App without Kubernetes (KinD Disabled)
If your repository does not deploy to Kubernetes, turn off KinD cluster testing by setting `kind-enabled: "false"`.

```yaml
- name: Run Supply Chain Guardian (KinD Disabled)
  uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
  with:
    dockerfile: './Dockerfile'
    kind-enabled: 'false'
    healthz-port: '5000'
    healthz-path: '/health'
    create-pr: 'true'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### 5. Full Production Setup (KinD Testing + Auto PR)
Runs complete scanning, AI remediation, KinD deployment test, and opens an automated security PR.

```yaml
name: Supply Chain Security Pipeline

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily security check at 2:00 AM

permissions:
  contents: write
  pull-requests: write

jobs:
  guardian-security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Supply Chain Guardian
        uses: barbaria888/SupplyChain-Guardian-AI-Github_Action@v2
        with:
          dockerfile: './backend/Dockerfile'
          provider: 'openai'
          model: 'deepseek-ai/deepseek-v4-flash'
          openai-endpoint: 'https://integrate.api.nvidia.com/v1'
          api-key: ${{ secrets.NVIDIA_NIM_API_KEY }}
          kind-enabled: 'true'
          k8s-manifests: './k8s/'
          healthz-port: '8080'
          healthz-path: '/healthz'
          create-pr: 'true'
          pr-branch: 'security/auto-cve-patch'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 🤖 Supported AI Providers

You can switch between local CPU inference and cloud API providers using the `provider` and `openai-endpoint` inputs:

| Provider | `provider` | `openai-endpoint` | Recommended Models |
|---|---|---|---|
| **Local Ollama** (Free) | `ollama` | *N/A* | `llama3.2:1b` *(default)* |
| **NVIDIA NIM** | `openai` | `https://integrate.api.nvidia.com/v1` | `moonshotai/kimi-k2.6`, `deepseek-ai/deepseek-v4-flash`, `z-ai/glm-5.2` |
| **OpenAI Direct** | `openai` | `https://api.openai.com/v1` | `gpt-4o-mini`, `gpt-4o` |
| **Groq / DeepSeek / Custom** | `openai` | *(Your base URL)* | Any OpenAI-compatible model |

---

## 📋 Complete Inputs & Outputs

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `dockerfile` | No | `./Dockerfile` | Path to the Dockerfile to scan and remediate |
| `image-ref` | No | `''` | Pre-built image reference (if scanning existing image) |
| `severity` | No | `CRITICAL,HIGH` | Comma-separated Trivy vulnerability severities |
| `provider` | No | `ollama` | AI engine: `ollama` or `openai` |
| `model` | No | *(auto)* | Model tag or identifier for the provider |
| `api-key` | No | `''` | API Key for cloud providers (NVIDIA / OpenAI / Custom) |
| `openai-endpoint` | No | `https://integrate.api.nvidia.com/v1` | OpenAI-compatible endpoint URL |
| `trivy-version` | No | `0.63.0` | Trivy CLI version |
| `kind-enabled` | No | `true` | Set to `"false"` to skip KinD Kubernetes integration tests |
| `kind-config` | No | `.kind/cluster-config.yaml` | Path to custom KinD cluster config |
| `k8s-manifests` | No | `k8s/` | Directory containing Kubernetes manifests to test in KinD |
| `healthz-port` | No | `18080` | Container host port mapped during health check |
| `healthz-path` | No | `/` | Endpoint path probed during container smoke test |
| `create-pr` | No | `true` | Set to `"true"` to open a PR on successful patch |
| `pr-branch` | No | `auto-patcher/cve-remediation` | Branch name used for the automated PR |
| `pr-labels` | No | `security,automated-patch` | Comma-separated labels applied to the PR |
| `enforce-non-root` | No | `true` | Enforces non-root execution (`USER` instruction) in patched Dockerfiles |
| `policy-preset` | No | `strict` | Enforcement mode: `strict` (fail on unresolved CVE) or `lax` (warn only) |

### Outputs

| Output | Description |
|---|---|
| `vulnerabilities-found` | `"true"` if Trivy detected matching vulnerabilities |
| `patch-applied` | `"true"` if AI successfully generated a patch |
| `smoke-test-passed` | `"true"` if the patched Dockerfile built and booted cleanly |
| `kind-validation-passed` | `"true"` if KinD Kubernetes deployment test succeeded |

---

## 🛡️ Security & Reliability Features

* 🔒 **Zero Egress Option**: Use `provider: 'ollama'` for 100% offline, privacy-first patching directly inside the GitHub Actions runner.
* 🛡️ **3-Layer Hallucination Defense**:
  1. **Syntax Whitelist**: Inspects generated Dockerfile instructions (`FROM`, `RUN`, `COPY`, etc.) to prevent LLM hallucinations.
  2. **Smoke Test Gate**: Verifies `docker build` and runtime container stability (with dummy DB env injection for app boots).
  3. **KinD Cluster Verification**: Ensures the container deploys into Kubernetes without `CrashLoopBackOff`.
* 📜 **Full Auditability**: Every run generates a `patch_audit.log` artifact containing full LLM prompts, raw outputs, and scan reports.

---

## ❓ FAQ & Troubleshooting

### Why is the PR creation step failing?
Ensure your workflow file includes the required permissions:
```yaml
permissions:
  contents: write
  pull-requests: write
```
Also ensure you pass the `GITHUB_TOKEN` environment variable:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Why did the KinD validation step fail with `ErrImageNeverPull`?
Starting in **v2.4.0**, all discovered Kubernetes manifests automatically have their container `image:` replaced with the locally built patched image (`guardian-scan:patched`) and `imagePullPolicy: Never`. Make sure you are using `@v2` (or `@v2.4.0`+). If your repository does not use Kubernetes, simply set `kind-enabled: "false"`.

---

## License

[MIT License](./LICENSE) — Created by [@barbaria888](https://github.com/barbaria888).
