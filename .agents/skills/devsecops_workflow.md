# Skill: Proactive DevSecOps Supply Chain Guardian Workflow

**Version:** 1.0.0  
**Last Updated:** 2026-06-01  
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
problems, the AI fixes them, the cluster validates the fix, and a
human-reviewable PR is the final artifact.

```
┌────────────────────────────────────────────────────────────────────┐
│                    SUPPLY CHAIN GUARDIAN LOOP                      │
│                                                                    │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌─────────────┐  │
│  │ @SecOps │───▶│@AIPatcher│───▶│   @SRE   │───▶│  PR + Audit │  │
│  │  Scan   │    │  Patch   │    │ Validate │    │    Trail    │  │
│  └─────────┘    └──────────┘    └──────────┘    └─────────────┘  │
│       │                │               │                           │
│   trivy-results     LLM call       KinD deploy               GitHub PR  │
│   .json output    + Dockerfile   + health check           + SBOM diff  │
└────────────────────────────────────────────────────────────────────┘
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

**Gate:** If zero CRITICAL/HIGH CVEs are found, the pipeline exits
cleanly with a success status. No AI call is made. This is a cost and
latency optimization.

---

### 2. @AIPatcher → @SRE (The Patch Delivery)

**Trigger:** `scripts/remediate_cve.py` successfully extracts a valid
Dockerfile patch from the Ollama LLM response.

**Artifact Produced:** An overwritten `Dockerfile` with updated base
image and/or dependency pins. A companion `patch_audit.log` is written
alongside it, recording the exact prompt sent, the raw LLM response,
and the parsed patch applied.

**Contract:** The `@AIPatcher` must NEVER modify files in the `k8s/`
directory. Kubernetes manifest patching is exclusively `@SRE`'s domain.
If a CVE requires a manifest change (e.g., a network policy), the
`@AIPatcher` must flag it in `patch_audit.log` as `REQUIRES_SRE_REVIEW`
and halt its own job with a non-zero exit code.

**Validation Hook:** Before writing the patched Dockerfile, the script
runs a syntax check using `docker build --no-cache --dry-run` (if
available) or a regex guard to confirm the output contains `FROM`,
`WORKDIR`, and `CMD`/`ENTRYPOINT` lines.

---

### 3. @SRE → PR Gate (The Proof)

**Trigger:** The patched Docker image builds successfully and is loaded
into the ephemeral KinD cluster.

**Artifact Produced:** A `kind-test-report.txt` capturing the output of:
- `kubectl get pods -A`
- `kubectl describe deployment/<app-name>`
- The re-run Trivy scan result showing 0 CRITICAL CVEs on the new image.

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
| `kind-test-report.txt` | @SRE | Cluster validation evidence |
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

---

## Skill Dependencies

- **Trivy:** v0.55.0+ (for SBOM and supply chain scanning support)
- **Ollama:** v0.3.0+ (for Llama 3.2 1B tool-calling support)
- **KinD:** v0.23.0+
- **Python:** 3.12+ (for `scripts/`)
- **kubectl:** v1.30+
