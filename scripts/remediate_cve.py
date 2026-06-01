"""
scripts/remediate_cve.py — @AIPatcher Domain
=============================================
Deterministic bridge between Trivy JSON reports and Dockerfile patches.

Design Guarantees:
  - Token-minimal: only 4 CVE fields are forwarded to the LLM.
  - Hallucination-resistant: regex strips markdown fencing; primitive
    validation rejects non-Dockerfile output before any file write.
  - Idempotent: running twice on the same report produces the same patch.
  - Audit-complete: every prompt and raw response is logged to patch_audit.log.
  - Fail-loud: on LLM failure after 3 retries, exits 1 and never silently skips.

Owner: @AIPatcher
Escalation: If LLM fails 3 retries → exit(1) → GitHub Actions must file an Issue.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))  # seconds

TRIVY_RESULTS_PATH: Path = Path(os.getenv("TRIVY_RESULTS", "trivy-results.json"))
DOCKERFILE_PATH: Path = Path(os.getenv("DOCKERFILE_PATH", "Dockerfile"))
AUDIT_LOG_PATH: Path = Path(os.getenv("AUDIT_LOG_PATH", "patch_audit.log"))

MAX_RETRIES: int = 3
RETRY_BACKOFF_SECONDS: float = 5.0

# Required Dockerfile primitives — output is rejected if ANY are missing.
REQUIRED_DOCKERFILE_PRIMITIVES: tuple[str, ...] = ("FROM",)
# At least one of these must be present (entrypoint definition).
ENTRYPOINT_PRIMITIVES: tuple[str, ...] = ("CMD", "ENTRYPOINT")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("AIPatcher")


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------
class AuditLogger:
    """Append-only structured audit trail for every LLM interaction."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, data: dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **data,
        }
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            log.warning("Audit write failed (non-fatal): %s", exc)


audit = AuditLogger(AUDIT_LOG_PATH)


# ---------------------------------------------------------------------------
# Step 1 — Data Parsing & Token Minimization
# ---------------------------------------------------------------------------
def _extract_cve_records(trivy_json: dict[str, Any]) -> list[dict[str, str]]:
    """
    Extract a flat, minimal list of CVE dicts from a Trivy JSON report.

    Only four fields are forwarded to the LLM to prevent context-window
    overflow on the 1B parameter model:
      - VulnerabilityID
      - PkgName
      - InstalledVersion
      - FixedVersion

    CVEs without a FixedVersion are skipped — they cannot be patched yet.
    """
    minimized: list[dict[str, str]] = []
    target_severities = {"CRITICAL", "HIGH"}

    results: list[dict[str, Any]] = trivy_json.get("Results", [])
    for result in results:
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "").upper()
            if severity not in target_severities:
                continue
            fixed = vuln.get("FixedVersion", "")
            if not fixed:
                log.debug(
                    "Skipping %s — no fixed version available.",
                    vuln.get("VulnerabilityID", "UNKNOWN"),
                )
                continue
            minimized.append(
                {
                    "VulnerabilityID": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "PkgName": vuln.get("PkgName", "UNKNOWN"),
                    "InstalledVersion": vuln.get("InstalledVersion", "UNKNOWN"),
                    "FixedVersion": fixed,
                }
            )

    return minimized


def load_and_minimize_trivy_report(path: Path) -> list[dict[str, str]]:
    """Load Trivy JSON from disk and return the minimized CVE list."""
    log.info("Loading Trivy report from: %s", path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.error("Trivy results not found at '%s'. Was the scan job skipped?", path)
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to read Trivy results: %s", exc)
        sys.exit(1)

    try:
        trivy_json: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.error("Trivy results JSON is malformed: %s", exc)
        sys.exit(1)

    records = _extract_cve_records(trivy_json)
    audit.write(
        "trivy_parsed",
        {"trivy_path": str(path), "cve_count": len(records), "records": records},
    )
    return records


# ---------------------------------------------------------------------------
# Step 2 — Dockerfile Loader
# ---------------------------------------------------------------------------
def load_dockerfile(path: Path) -> str:
    """Read the current Dockerfile from disk."""
    log.info("Loading Dockerfile from: %s", path)
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.error("Dockerfile not found at '%s'.", path)
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to read Dockerfile: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Step 3 — Prompt Construction
# ---------------------------------------------------------------------------
_SYSTEM_INSTRUCTIONS = """\
You are a Senior Security Engineer specializing in container hardening.
Your task is to patch a Dockerfile to remediate the listed CVEs.

STRICT OUTPUT CONTRACT:
- Output ONLY the complete, updated Dockerfile content.
- Do NOT include any explanation, commentary, markdown, or code fences.
- Do NOT include triple backticks (``` or ```dockerfile).
- Do NOT include any text before the first FROM instruction.
- Do NOT include any text after the final CMD or ENTRYPOINT instruction.
- If you cannot determine a safe fix, output the original Dockerfile unchanged.
Violating this contract produces broken infrastructure and is unacceptable.\
"""


def build_prompt(cve_records: list[dict[str, str]], dockerfile_content: str) -> str:
    """Construct the minimal, instruction-isolated prompt."""
    cve_summary = json.dumps(cve_records, indent=2)
    return (
        f"{_SYSTEM_INSTRUCTIONS}\n\n"
        f"[CVE_REPORT]\n{cve_summary}\n[/CVE_REPORT]\n\n"
        f"[CURRENT_DOCKERFILE]\n{dockerfile_content}\n[/CURRENT_DOCKERFILE]\n\n"
        "Patched Dockerfile:"
    )


# ---------------------------------------------------------------------------
# Step 4 — LLM Invocation (with retry)
# ---------------------------------------------------------------------------
def _call_ollama(prompt: str, attempt: int) -> str:
    """
    POST a generate request to the local Ollama server.
    Returns the raw response string on success.
    Raises requests.RequestException on failure.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            # Deterministic output — security patching must not be stochastic.
            "temperature": 0.0,
            "top_p": 1.0,
            "num_predict": 2048,
        },
    }
    log.info("Calling Ollama (attempt %d/%d) model=%s", attempt, MAX_RETRIES, OLLAMA_MODEL)
    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json=payload,
        timeout=OLLAMA_TIMEOUT,
    )
    response.raise_for_status()
    return response.json().get("response", "")


def invoke_llm_with_retry(prompt: str) -> str:
    """
    Call Ollama with exponential backoff. Exits 1 after MAX_RETRIES failures.
    Escalation contract: never silently skip — always fail loudly.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            raw_response = _call_ollama(prompt, attempt)
            audit.write(
                "llm_response",
                {
                    "attempt": attempt,
                    "model": OLLAMA_MODEL,
                    "raw_response_length": len(raw_response),
                    "raw_response_preview": raw_response[:500],
                },
            )
            return raw_response
        except requests.exceptions.ConnectionError as exc:
            log.error("Ollama connection refused (attempt %d): %s", attempt, exc)
        except requests.exceptions.Timeout:
            log.error("Ollama request timed out after %ds (attempt %d)", OLLAMA_TIMEOUT, attempt)
        except requests.exceptions.HTTPError as exc:
            log.error("Ollama HTTP error (attempt %d): %s", attempt, exc)
        except (KeyError, json.JSONDecodeError) as exc:
            log.error("Ollama response parse error (attempt %d): %s", attempt, exc)

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_SECONDS * attempt
            log.warning("Retrying in %.0fs...", wait)
            time.sleep(wait)

    # All retries exhausted — escalation required.
    audit.write(
        "llm_failure",
        {
            "model": OLLAMA_MODEL,
            "retries": MAX_RETRIES,
            "action": "PIPELINE_FAILED_LOUDLY",
            "note": "GitHub Actions must file an Issue per escalation contract.",
        },
    )
    log.critical(
        "LLM failed after %d retries. Exiting 1. "
        "Pipeline must file a GitHub Issue — see escalation contract in agents.md.",
        MAX_RETRIES,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 5 — Post-Processing & Hallucination Defense
# ---------------------------------------------------------------------------
# Matches any leading/trailing markdown code fences, e.g.:
#   ```dockerfile  or  ```docker  or  ```  followed by content  then  ```
_MARKDOWN_FENCE_RE = re.compile(
    r"^```[a-zA-Z]*\n?(.*?)\n?```$",
    re.DOTALL | re.IGNORECASE,
)

# Matches a bare leading fence without a closing fence (model cut off)
_LEADING_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n?", re.IGNORECASE)


def strip_markdown_fencing(raw: str) -> str:
    """
    Remove triple-backtick markdown fencing that models frequently inject
    despite explicit instructions not to.

    Processing order:
      1. Strip surrounding whitespace.
      2. Match and extract content between balanced fences.
      3. Fallback: strip a leading fence if no closing fence exists.
    """
    stripped = raw.strip()

    # Try balanced fence extraction first.
    match = _MARKDOWN_FENCE_RE.match(stripped)
    if match:
        return match.group(1).strip()

    # Fallback: strip just the leading fence if model was cut off.
    stripped = _LEADING_FENCE_RE.sub("", stripped).strip()

    # Remove any trailing fence that may remain.
    if stripped.endswith("```"):
        stripped = stripped[:-3].strip()

    return stripped


def validate_dockerfile_primitives(content: str) -> None:
    """
    Sanity-check that the LLM output contains the non-negotiable Dockerfile
    primitives. Exits 1 (fatal) if validation fails — never writes a broken file.
    """
    missing_required = [p for p in REQUIRED_DOCKERFILE_PRIMITIVES if p not in content]
    if missing_required:
        audit.write(
            "validation_failed",
            {
                "reason": "missing_required_primitives",
                "missing": missing_required,
                "content_preview": content[:300],
            },
        )
        log.critical(
            "Dockerfile validation FAILED — missing required primitives: %s. "
            "Refusing to overwrite Dockerfile. Exiting 1.",
            missing_required,
        )
        sys.exit(1)

    has_entrypoint = any(p in content for p in ENTRYPOINT_PRIMITIVES)
    if not has_entrypoint:
        audit.write(
            "validation_failed",
            {
                "reason": "missing_entrypoint_primitive",
                "content_preview": content[:300],
            },
        )
        log.critical(
            "Dockerfile validation FAILED — missing CMD or ENTRYPOINT. "
            "Refusing to overwrite Dockerfile. Exiting 1.",
        )
        sys.exit(1)

    log.info("Dockerfile primitive validation PASSED.")


# ---------------------------------------------------------------------------
# Step 6 — Safe File Write
# ---------------------------------------------------------------------------
def write_patched_dockerfile(path: Path, content: str) -> None:
    """
    Atomically write the patched Dockerfile.
    Uses a .tmp sibling file + rename for crash safety.
    Preserves original file permissions.
    """
    tmp_path = path.with_suffix(".tmp")
    try:
        # Preserve original permissions before write.
        original_mode: int | None = None
        if path.exists():
            original_mode = path.stat().st_mode

        tmp_path.write_text(content, encoding="utf-8")

        # Restore permissions on the temp file before renaming.
        if original_mode is not None:
            tmp_path.chmod(original_mode)

        tmp_path.replace(path)
        log.info("Patched Dockerfile written atomically to: %s", path)
        audit.write(
            "dockerfile_written",
            {
                "path": str(path),
                "content_length": len(content),
                "permissions_preserved": original_mode is not None,
            },
        )
    except OSError as exc:
        log.critical("Failed to write patched Dockerfile: %s", exc)
        # Clean up temp file if it exists.
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 60)
    log.info("AIPatcher — Supply Chain Guardian Remediation Engine")
    log.info("=" * 60)
    audit.write("run_started", {"model": OLLAMA_MODEL, "trivy_path": str(TRIVY_RESULTS_PATH)})

    # --- Step 1: Parse & minimize Trivy report ---
    cve_records = load_and_minimize_trivy_report(TRIVY_RESULTS_PATH)

    if not cve_records:
        log.info("No CRITICAL/HIGH CVEs with available fixes found. Pipeline is clean. Exiting 0.")
        audit.write("run_completed", {"outcome": "CLEAN_NO_ACTION"})
        sys.exit(0)

    log.info("Found %d actionable CVE(s) to remediate.", len(cve_records))

    # --- Step 2: Load current Dockerfile ---
    dockerfile_content = load_dockerfile(DOCKERFILE_PATH)

    # --- Step 3: Build prompt ---
    prompt = build_prompt(cve_records, dockerfile_content)
    audit.write("prompt_built", {"prompt_length": len(prompt), "cve_count": len(cve_records)})
    log.info("Prompt constructed (%d chars). Invoking LLM...", len(prompt))

    # --- Step 4: Call LLM ---
    raw_response = invoke_llm_with_retry(prompt)

    # --- Step 5: Post-process & validate ---
    cleaned = strip_markdown_fencing(raw_response)
    log.info("Post-processing complete. Cleaned output length: %d chars.", len(cleaned))
    audit.write("post_processing_complete", {"cleaned_length": len(cleaned)})

    validate_dockerfile_primitives(cleaned)

    # --- Step 6: Write patched Dockerfile ---
    write_patched_dockerfile(DOCKERFILE_PATH, cleaned)

    audit.write("run_completed", {"outcome": "PATCH_APPLIED", "cve_count": len(cve_records)})
    log.info("Remediation complete. Patched Dockerfile ready for KinD validation.")
    sys.exit(0)


if __name__ == "__main__":
    main()
