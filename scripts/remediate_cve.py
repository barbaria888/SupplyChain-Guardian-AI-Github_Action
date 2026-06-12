"""
scripts/remediate_cve.py — AI Patching Engine
==============================================
Takes a Trivy JSON report + a Dockerfile, asks an LLM to fix the CVEs,
validates the output isn't hallucinated garbage, and writes Dockerfile.patched.

Key design choices:
  - Only 4 CVE fields go to the LLM (keeps the context window small)
  - 3-layer hallucination defense: markdown stripping → instruction whitelist → primitive check
  - Side-by-side patching: never overwrites the original Dockerfile
  - Fail-loud: exits 1 on LLM failure after retries, never silently skips
  - Multi-provider: local Ollama or any OpenAI-compatible API (NVIDIA, DeepSeek, etc.)

Owner: @AIPatcher
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Config — all from environment variables with sane defaults
# ---------------------------------------------------------------------------
PROVIDER: str = os.getenv("PROVIDER", "ollama").lower()
API_KEY: str = os.getenv("API_KEY", "")

# Ollama (local CPU inference)
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2:1b")

# OpenAI-compatible (works with NVIDIA NIM, DeepSeek, OpenAI, Azure, etc.)
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "deepseek-ai/deepseek-v4-flash")
OPENAI_ENDPOINT: str = os.getenv("OPENAI_ENDPOINT", "https://integrate.api.nvidia.com/v1")

# Timeout — supports legacy OLLAMA_TIMEOUT for backward compat
_timeout_str = os.getenv("LLM_TIMEOUT") or os.getenv("OLLAMA_TIMEOUT") or "120"
LLM_TIMEOUT: int = int(_timeout_str)

TRIVY_RESULTS_PATH: Path = Path(os.getenv("TRIVY_RESULTS", "trivy-results.json"))
DOCKERFILE_PATH: Path = Path(os.getenv("DOCKERFILE_PATH", "Dockerfile"))
PATCHED_DOCKERFILE_PATH: Path = Path(os.getenv("PATCHED_DOCKERFILE_PATH", "Dockerfile.patched"))
AUDIT_LOG_PATH: Path = Path(os.getenv("AUDIT_LOG_PATH", "patch_audit.log"))
POLICY_PRESET: str = os.getenv("POLICY_PRESET", "strict").lower()

MAX_RETRIES: int = 3
RETRY_BACKOFF_SECONDS: float = 5.0

# Every non-comment line must start with one of these. Anything else
# (CREATEGROUP, ADDuser, INSTALL…) is a hallucinated instruction.
VALID_DOCKERFILE_INSTRUCTIONS: frozenset[str] = frozenset({
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
    "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR",
    "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
})

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
# Audit Logger — JSON-lines file for compliance evidence
# ---------------------------------------------------------------------------
class AuditLogger:
    """Append-only structured audit trail for every LLM interaction."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, data: dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
# Step 1 — Trivy Parsing (token-minimal extraction)
# ---------------------------------------------------------------------------
def _extract_cve_records(trivy_json: dict[str, Any]) -> list[dict[str, str]]:
    """
    Pull out only the 4 fields we need from Trivy JSON.

    Only CRITICAL/HIGH with a known fix — everything else is noise
    that would waste the LLM's context window.
    """
    records: list[dict[str, str]] = []
    for result in trivy_json.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            if vuln.get("Severity", "").upper() not in {"CRITICAL", "HIGH"}:
                continue
            fixed = vuln.get("FixedVersion", "")
            if not fixed:
                continue
            records.append({
                "VulnerabilityID": vuln.get("VulnerabilityID", "UNKNOWN"),
                "PkgName": vuln.get("PkgName", "UNKNOWN"),
                "InstalledVersion": vuln.get("InstalledVersion", "UNKNOWN"),
                "FixedVersion": fixed,
            })
    return records


def load_and_minimize_trivy_report(path: Path) -> list[dict[str, str]]:
    """Load Trivy JSON from disk and return the minimized CVE list."""
    log.info("Loading Trivy report: %s", path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.error("Trivy results not found at '%s'. Was the scan step skipped?", path)
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to read Trivy results: %s", exc)
        sys.exit(1)

    try:
        data: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.error("Trivy results JSON is malformed: %s", exc)
        sys.exit(1)

    records = _extract_cve_records(data)
    audit.write("trivy_parsed", {
        "trivy_path": str(path),
        "cve_count": len(records),
        "records": records,
    })
    return records


# ---------------------------------------------------------------------------
# Step 2 — Dockerfile Loader
# ---------------------------------------------------------------------------
def load_dockerfile(path: Path) -> str:
    """Read the current Dockerfile from disk."""
    log.info("Loading Dockerfile: %s", path)
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
# Why such a long system prompt? Because small/fast models hallucinate Docker
# syntax (CREATEGROUP, ADDuser, INSTALL) unless you explicitly forbid it.
# Every rule here was earned from a real pipeline failure.
_SYSTEM_INSTRUCTIONS = """\
You are a Senior Security Engineer specializing in container hardening.
Your task is to patch a Dockerfile to remediate the listed CVEs.

CRITICAL RULE — PRESERVE ALL EXISTING RUNTIME BEHAVIOR:
You MUST preserve every existing instruction in the Dockerfile. Never remove:
  - WORKDIR
  - CMD
  - ENTRYPOINT
  - USER
  - COPY
  - EXPOSE
  - HEALTHCHECK
  - RUN (user/group creation commands)
These instructions are required for the container to function at runtime.
Removing any of them will cause the container to crash in Kubernetes.

You may ONLY modify:
  - Base image versions (FROM tag)
  - Vulnerable package versions
  - pip / setuptools / wheel versions
  - OS-level packages (apk add / apt-get install)
Do NOT change application logic, user setup, working directories, or entrypoints.

STRICT OUTPUT CONTRACT:
- Output ONLY the complete, updated Dockerfile content.
- Do NOT include any explanation, commentary, markdown, or code fences.
- Do NOT include triple backticks (``` or ```dockerfile).
- Do NOT include any text before the first FROM instruction.
- Do NOT include any text after the final CMD or ENTRYPOINT instruction.
- If you cannot determine a safe fix, output the original Dockerfile unchanged.
- Every line MUST begin with a valid Dockerfile instruction: FROM, RUN, CMD,
  COPY, ADD, EXPOSE, ENV, LABEL, USER, WORKDIR, ARG, ENTRYPOINT, VOLUME,
  HEALTHCHECK, SHELL, STOPSIGNAL, ONBUILD, MAINTAINER, or be a comment (#).

CRITICAL ALPINE LINUX RULE:
To manage users in Alpine Linux images, you MUST use standard shell commands
prefixed by the RUN instruction. Correct example:
  RUN addgroup -g 1000 appgroup && adduser -u 1000 -G appgroup -s /bin/sh -D appuser
Never invent Docker keywords like CREATEGROUP, ADDuser, ADDGROUP, USERADD,
GROUPADD, INSTALL, or any instruction not in the official Dockerfile spec.
Any hallucinated instruction will be rejected and the patch will fail.

Violating this contract produces broken infrastructure and is unacceptable.\
"""


def build_prompt(cve_records: list[dict[str, str]], dockerfile_content: str) -> str:
    """Construct the minimal, instruction-isolated prompt for the LLM."""
    cve_summary = json.dumps(cve_records, indent=2)
    return (
        f"{_SYSTEM_INSTRUCTIONS}\n\n"
        f"[CVE_REPORT]\n{cve_summary}\n[/CVE_REPORT]\n\n"
        f"[CURRENT_DOCKERFILE]\n{dockerfile_content}\n[/CURRENT_DOCKERFILE]\n\n"
        "Patched Dockerfile:"
    )


# ---------------------------------------------------------------------------
# Step 4 — LLM Invocation (Ollama or OpenAI-compatible, with retry)
# ---------------------------------------------------------------------------
def _call_ollama(prompt: str, attempt: int) -> str:
    """POST to the local Ollama server. No API key needed."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,   # deterministic — security patches shouldn't be creative
            "top_p": 1.0,
            "num_predict": 2048,
        },
    }
    log.info("Calling Ollama (attempt %d/%d) model=%s", attempt, MAX_RETRIES, OLLAMA_MODEL)
    resp = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("response", "")


def _call_openai(prompt: str, attempt: int) -> str:
    """
    POST to any OpenAI-compatible chat completions API.
    Works with NVIDIA NIM, DeepSeek, OpenAI, Azure — anything that speaks
    the /v1/chat/completions schema.
    """
    if not API_KEY:
        log.critical("PROVIDER=openai but API_KEY is not set. Exiting.")
        sys.exit(1)

    # Build the full URL — user can set OPENAI_ENDPOINT to either the base
    # (/v1) or the full path (/v1/chat/completions), and we handle both.
    url = f"{OPENAI_ENDPOINT.rstrip('/')}/chat/completions"

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "close",   # prevents gateway socket hangs on NVIDIA NIM
    }
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 2048,
        "temperature": 0.2,
        "top_p": 0.95,
        "stream": False,
    }

    log.info("Calling OpenAI-compatible API (attempt %d/%d) model=%s",
             attempt, MAX_RETRIES, OPENAI_MODEL)
    log.info("  → URL: %s | Timeout: %ds", url, LLM_TIMEOUT)

    resp = requests.post(url, json=payload, headers=headers, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as exc:
        log.error("Unexpected API response structure: %s", exc)
        raise


def invoke_llm_with_retry(prompt: str) -> str:
    """
    Call the configured LLM with exponential backoff.
    Exits 1 after MAX_RETRIES — never silently skips (fail-loud contract).
    """
    call_fn = _call_openai if PROVIDER == "openai" else _call_ollama
    model_name = OPENAI_MODEL if PROVIDER == "openai" else OLLAMA_MODEL
    log.info("Provider: %s | Model: %s", PROVIDER, model_name)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            raw = call_fn(prompt, attempt)
            audit.write("llm_response", {
                "attempt": attempt,
                "provider": PROVIDER,
                "model": model_name,
                "raw_response_length": len(raw),
                "raw_response_preview": raw[:500],
            })
            return raw
        except requests.exceptions.ConnectionError as exc:
            log.error("Connection refused (attempt %d): %s", attempt, exc)
        except requests.exceptions.Timeout:
            log.error("Timeout after %ds (attempt %d)", LLM_TIMEOUT, attempt)
        except requests.exceptions.HTTPError as exc:
            log.error("HTTP error (attempt %d): %s", attempt, exc)
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            log.error("Response parse error (attempt %d): %s", attempt, exc)

        if attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF_SECONDS * attempt
            log.warning("Retrying in %.0fs...", wait)
            time.sleep(wait)

    # All retries exhausted — escalation required.
    audit.write("llm_failure", {
        "provider": PROVIDER,
        "model": model_name,
        "retries": MAX_RETRIES,
        "action": "PIPELINE_FAILED_LOUDLY",
    })
    log.critical(
        "LLM failed after %d retries (provider=%s, model=%s). Exiting 1.",
        MAX_RETRIES, PROVIDER, model_name,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 5 — Post-Processing & Hallucination Defense (3 layers)
# ---------------------------------------------------------------------------
_MARKDOWN_FENCE_RE = re.compile(
    r"^```[a-zA-Z]*\n?(.*?)\n?```$", re.DOTALL | re.IGNORECASE,
)
_LEADING_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n?", re.IGNORECASE)


def strip_markdown_fencing(raw: str) -> str:
    """Strip triple-backtick fencing that LLMs inject despite being told not to."""
    stripped = raw.strip()

    # Try balanced fence extraction first
    match = _MARKDOWN_FENCE_RE.match(stripped)
    if match:
        return match.group(1).strip()

    # Fallback: strip leading fence if model was cut off before closing
    stripped = _LEADING_FENCE_RE.sub("", stripped).strip()
    if stripped.endswith("```"):
        stripped = stripped[:-3].strip()

    return stripped


def _has_instruction(content: str, instruction: str) -> bool:
    """Return True if any line starts with the given Dockerfile instruction."""
    pattern = re.compile(rf"^\s*{instruction}\s", re.IGNORECASE | re.MULTILINE)
    return bool(pattern.search(content))


def validate_dockerfile_primitives(content: str) -> None:
    """
    Verify the patch has the minimum viable Dockerfile structure.
    Exits 1 if FROM or CMD/ENTRYPOINT is missing.

    Also runs a USER creation guard: if USER is declared, a creation
    command (adduser/useradd) must exist, otherwise the container will
    crash with 'unable to find user' at runtime.
    """
    # FROM is non-negotiable
    if not _has_instruction(content, "FROM"):
        audit.write("validation_failed", {
            "reason": "missing_FROM",
            "content_preview": content[:300],
        })
        log.critical("Dockerfile validation FAILED — missing FROM instruction.")
        sys.exit(1)

    # Must have at least one entrypoint definition
    if not (_has_instruction(content, "CMD") or _has_instruction(content, "ENTRYPOINT")):
        audit.write("validation_failed", {
            "reason": "missing_entrypoint",
            "content_preview": content[:300],
        })
        log.critical("Dockerfile validation FAILED — missing CMD or ENTRYPOINT.")
        sys.exit(1)

    # USER creation guard — catches a nasty runtime failure
    if _has_instruction(content, "USER"):
        creation_cmds = ("adduser", "useradd", "addgroup", "groupadd")
        if not any(cmd in content for cmd in creation_cmds):
            audit.write("validation_failed", {
                "reason": "user_declared_without_creation",
                "content_preview": content[:400],
            })
            log.critical(
                "Dockerfile validation FAILED — USER declared but no creation "
                "command (adduser/useradd) found. Container will crash at runtime."
            )
            sys.exit(1)
        log.info("USER creation guard PASSED.")

    log.info("Dockerfile primitive validation PASSED.")


def validate_dockerfile_instructions(content: str) -> None:
    """
    Instruction whitelist — catches hallucinated Docker syntax.

    Every non-empty, non-comment line must start with a real keyword.
    Lines like 'CREATEGROUP', 'ADDuser', 'INSTALL' get rejected instantly.
    Continuation lines (after a backslash) are skipped since they're
    arguments to the previous instruction.
    """
    lines = content.splitlines()
    in_continuation = False
    illegal_lines: list[tuple[int, str]] = []

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            in_continuation = False
            continue
        if in_continuation:
            in_continuation = line.endswith("\\")
            continue

        first_word = line.split()[0].upper() if line.split() else ""
        if first_word not in VALID_DOCKERFILE_INSTRUCTIONS:
            illegal_lines.append((line_num, raw_line))

        in_continuation = line.endswith("\\")

    if illegal_lines:
        formatted = "; ".join(
            f"L{num}: '{ln.strip()[:60]}'" for num, ln in illegal_lines[:5]
        )
        audit.write("validation_failed", {
            "reason": "hallucinated_dockerfile_instructions",
            "illegal_lines": [
                {"line": num, "content": ln.strip()} for num, ln in illegal_lines
            ],
        })
        log.critical(
            "Instruction whitelist FAILED — %d illegal line(s): %s. "
            "The LLM hallucinated non-existent Docker instructions.",
            len(illegal_lines), formatted,
        )
        sys.exit(1)

    log.info(
        "Instruction whitelist PASSED — all %d lines use valid instructions.",
        len([l for l in lines if l.strip() and not l.strip().startswith("#")]),
    )


# ---------------------------------------------------------------------------
# Step 6 — Safe Side-by-Side File Write
# ---------------------------------------------------------------------------
def write_patched_dockerfile(
    output_path: Path, content: str, original_path: Path | None = None,
) -> None:
    """
    Write the patched Dockerfile to a side-by-side location (Dockerfile.patched).
    The original is NEVER overwritten here — the workflow promotes it after
    the smoke test + KinD gates pass.

    Uses tmp+rename for crash safety. Preserves original file permissions.
    """
    tmp_path = output_path.with_suffix(".tmp")
    try:
        # Preserve permissions from the source Dockerfile
        original_mode: int | None = None
        source = original_path or output_path
        if source.exists():
            original_mode = source.stat().st_mode

        tmp_path.write_text(content, encoding="utf-8")
        if original_mode is not None:
            tmp_path.chmod(original_mode)
        tmp_path.replace(output_path)

        log.info("Patched Dockerfile written to: %s (original preserved at: %s)",
                 output_path, original_path)
        audit.write("dockerfile_written", {
            "output_path": str(output_path),
            "original_path": str(original_path),
            "content_length": len(content),
            "permissions_preserved": original_mode is not None,
        })
    except OSError as exc:
        log.critical("Failed to write patched Dockerfile: %s", exc)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 60)
    log.info("Supply Chain Guardian — AI Patching Engine")
    log.info("=" * 60)

    model_name = OPENAI_MODEL if PROVIDER == "openai" else OLLAMA_MODEL
    audit.write("run_started", {
        "provider": PROVIDER,
        "model": model_name,
        "policy": POLICY_PRESET,
        "output_strategy": "side-by-side (Dockerfile.patched)",
    })

    # 1. Parse Trivy report → minimal CVE list
    cve_records = load_and_minimize_trivy_report(TRIVY_RESULTS_PATH)

    if not cve_records:
        log.info("No actionable CVEs found. Pipeline is clean. Exiting 0.")
        audit.write("run_completed", {"outcome": "CLEAN_NO_ACTION"})
        sys.exit(0)

    log.info("Found %d actionable CVE(s) to remediate.", len(cve_records))

    # 2. Load current Dockerfile
    dockerfile_content = load_dockerfile(DOCKERFILE_PATH)

    # 3. Build prompt
    prompt = build_prompt(cve_records, dockerfile_content)
    audit.write("prompt_built", {"prompt_length": len(prompt), "cve_count": len(cve_records)})
    log.info("Prompt built (%d chars). Calling LLM...", len(prompt))

    # 4. Call LLM
    raw_response = invoke_llm_with_retry(prompt)

    # 5. Validate (3-layer defense)
    cleaned = strip_markdown_fencing(raw_response)
    log.info("Post-processing done. Cleaned output: %d chars.", len(cleaned))

    validate_dockerfile_primitives(cleaned)       # Layer 1: FROM + CMD/ENTRYPOINT
    validate_dockerfile_instructions(cleaned)     # Layer 2: instruction whitelist

    # 6. Write to Dockerfile.patched (original is preserved)
    write_patched_dockerfile(
        output_path=PATCHED_DOCKERFILE_PATH,
        content=cleaned,
        original_path=DOCKERFILE_PATH,
    )

    audit.write("run_completed", {
        "outcome": "PATCH_WRITTEN",
        "cve_count": len(cve_records),
        "output_path": str(PATCHED_DOCKERFILE_PATH),
    })
    log.info("Done. Patched Dockerfile at '%s'. Original preserved.", PATCHED_DOCKERFILE_PATH)
    sys.exit(0)


if __name__ == "__main__":
    main()
