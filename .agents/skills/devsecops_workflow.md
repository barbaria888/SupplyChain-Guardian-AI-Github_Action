# Skill: Proactive DevSecOps Supply Chain Guardian Workflow

**Version:** 2.0.0  
**Last Updated:** 2026-06-18  
**Maintained By:** @SecOps, @AIPatcher, @SRE

---

## Purpose

This document is the canonical reference for how the three agent
personas interact to form a closed-loop, self-patching security
pipeline. It is the "constitution" of the repository—every automation
decision traces back to the principles defined here.

---

## The Core Philosophy: Shift-Left Closed-Loop Security

Traditional DevSecOps is **detection-first**: scanners find problems
and file tickets. This pipeline is **remediation-first**: scanners find
problems, the AI fixes them, multi-gate validation proves the fix, and
a human-reviewable PR is the final artifact.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       SUPPLY CHAIN GUARDIAN LOOP (v2)                        │
│                                                                              │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌─────────────┐  │
│  │ @SecOps │─▶│@AIPatcher│─▶│ Integrity │─▶│ Smoke Test│─▶│    @SRE     │  │
│  │  Scan   │  │  Patch   │  │   Gate    │  │  + Health │  │  KinD Test  │  │
│  └─────────┘  └──────────┘  └───────────┘  └───────────┘  └──────┬──────┘  │
│       │              │             │              │               │          │
│  trivy-results   LLM call    Blueprint     Build+Run+DB     kubectl wait    │
│  .json output  + Dockerfile   check        injection       + health probe   │
│                  .patched                                                    │
│                                                              ┌──────────┐   │
│                                                              │ PR+Audit │   │
│                                                              │  Trail   │   │
│                                                              └──────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Domain Interaction Contract

### 1. @SecOps → @AIPatcher (The Handoff)

**Trigger:** Trivy finds one or more `CRITICAL` or `HIGH` severity CVEs.

**Artifact Produced:** `trivy-results.json` — a structured JSON report
containing full CVE metadata: CVE ID, severity, affected package,
fixed version, and description.

**Contract:** The JSON schema of `trivy-results.json` is stable. The
`@AIPatcher` reads it without transformation. If Trivy changes its
output schema, `@SecOps` is responsible for updating the schema adapter
in `scripts/schema_adapter.py`.

**Dynamic Build Context:** When the `dockerfile` input contains a path
separator (e.g., `./backend/Dockerfile`), the scan stage automatically
derives the Docker build context from `dirname` to support mono-repo
layouts without sending the entire repository root to the Docker daemon.

**Gate:** If zero CRITICAL/HIGH CVEs are found, the pipeline exits
cleanly with a success status. No AI call is made. This is a cost and
latency optimization.

---

### 2. @AIPatcher → Integrity Gate (The Patch Delivery)

**Trigger:** `scripts/remediate_cve.py` successfully extracts a valid
Dockerfile patch from the LLM response (Ollama, OpenAI, or NVIDIA NIM).

**Artifact Produced:** A `Dockerfile.patched` file written side-by-side
with the original (the original is **never touched** until all gates pass).
A companion `patch_audit.log` is written alongside it, recording the exact
prompt sent, the raw LLM response, and the parsed patch applied.

**Manifest-First Remediation Strategy:** The LLM system prompt instructs
the AI to fix vulnerabilities by pinning OS-level packages (`apk add` /
`apt-get install` version pins) rather than injecting inline `npm install`
or `pip install` commands. This prevents dependency collision loops and
corrupt `node_modules` / `site-packages` footprints.

**API Key Resolution:** The remediation engine resolves credentials via
`inputs.api-key` first, falling back to `env.API_KEY` from the step or
job environment. Secrets are never hardcoded.

**Contract:** The `@AIPatcher` must NEVER modify files in the `k8s/`
directory. Kubernetes manifest patching is exclusively `@SRE`'s domain.
If a CVE requires a manifest change (e.g., a network policy), the
`@AIPatcher` must flag it in `patch_audit.log` as `REQUIRES_SRE_REVIEW`
and halt its own job with a non-zero exit code.

---

### 3. Integrity Gate → Smoke Test (Adaptive Blueprint Validation)

**Trigger:** `Dockerfile.patched` is produced by the remediation engine.

**Validation Logic:**
- **Core Mandatory Instructions** (always enforced): `FROM`, `WORKDIR`,
  `COPY`, `EXPOSE`, `CMD`.
- **HEALTHCHECK**: Enforced only if the original Dockerfile contained one.
- **USER**: Enforced only when `enforce-non-root` is `true` (default) AND
  the original Dockerfile had a `USER` directive.

**Configurable Non-Root Policy:** The `enforce-non-root` input (default:
`true`) controls whether the integrity gate requires a `USER` instruction.
Setting it to `false` permits root-based container configurations for
base images or build-stage containers.

**Gate:** Missing any mandatory instruction causes the pipeline to fail
with a detailed error message listing the missing properties.

---

### 4. Smoke Test → @SRE (Build + Runtime + Health Probe)

**Trigger:** The integrity gate passes.

**Validation Stages:**
1. **Docker Build Gate**: `docker build -f Dockerfile.patched` must succeed.
2. **Runtime Stability**: Container must remain running for 15 seconds.
3. **Database Injection**: Dummy `MONGO_URI`, `DATABASE_URL`, and `SKIP_DB`
   environment variables are injected into the container to prevent apps
   with mandatory DB connections (Mongoose, PostgreSQL) from crashing.
4. **Health Probe**: 5 retries of `curl http://localhost:18080/healthz`.

---

### 5. @SRE → PR Gate (The Proof)

**Trigger:** The patched Docker image builds, boots, and passes the
health probe in the smoke test. KinD validation follows.

**Artifact Produced:** A `kind-diagnostics/` directory capturing:
- `all-pods.txt` — `kubectl get pods -A`
- `pod-describe.txt` — `kubectl describe pods`
- `events.txt` — cluster events sorted by timestamp
- Per-pod log files

**Contract:** The `@SRE`'s KinD validation job must run the patched
image through the *same* Kubernetes manifests in `k8s/` that exist in
production. It is not acceptable to use a simplified or stripped-down
manifest for testing.

**Merge Gate:** The `peter-evans/create-pull-request` action is only
invoked if ALL of the following are true:
1. `kubectl wait` returns 0 (all pods Ready).
2. Trivy re-scan of the patched image returns 0 CRITICAL CVEs.
3. `patch_audit.log` contains no `REQUIRES_SRE_REVIEW` flags.

---

## Audit Trail & Compliance

Every pipeline run produces the following artifacts, uploaded to the
GitHub Actions run summary:

| Artifact | Owner | Purpose |
|---|---|---|
| `trivy-results.json` | @SecOps | Original vulnerability report |
| `patch_audit.log` | @AIPatcher | Full prompt + LLM response log |
| `Dockerfile.patched` | @AIPatcher | The generated patch (for forensic review) |
| `kind-diagnostics/` | @SRE | Cluster validation evidence |
| `trivy-results-post-patch.json` | @SecOps | Proof of CVE remediation |

These artifacts are retained for **90 days** and can be used for SOC 2
or internal security audits to demonstrate that every automated change
was validated before being proposed for merge.

---

## Escalation Matrix

| Failure Condition | Action | Who Notified |
|---|---|---|
| CVSS ≥ 9.0 found | Pipeline pauses; human-approval gate required | Repo Owner via GitHub Issue |
| LLM fails 3 retries | Pipeline fails loudly; no silent skip | Repo Owner via GitHub Issue |
| KinD deploy fails (>120s) | Pipeline fails; detailed report filed | Repo Owner via GitHub Issue |
| Re-scan still shows CRITICAL | PR blocked; escalation issue filed | @SecOps + Repo Owner |
| Integrity gate FAILED | Pipeline blocks; missing instructions logged | @AIPatcher + Repo Owner |
| Smoke test container crash | Logs captured; DB injection verified | @SRE + Repo Owner |

---

## Skill Dependencies

- **Trivy:** v0.55.0+ (for SBOM and supply chain scanning support)
- **Ollama:** v0.3.0+ (for local inference; optional when using cloud providers)
- **KinD:** v0.23.0+
- **Python:** 3.12+ (for `scripts/`)
- **kubectl:** v1.30+
- **Docker:** v24.0+ (for `docker build` and `docker run` smoke tests)
