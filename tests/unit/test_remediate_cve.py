"""
tests/unit/test_remediate_cve.py — @AIPatcher Unit Tests
=========================================================
Tests the deterministic, non-LLM layers of the remediation engine:
  - Trivy JSON parsing and minimization
  - Markdown fence stripping (hallucination defense)
  - Dockerfile primitive validation
  - Dockerfile instruction whitelist (catches hallucinated Docker syntax)
  - Graceful early-exit on empty CVE list
  - Side-by-side file write behavior

These tests NEVER call Ollama — the LLM is mocked in all network tests.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Make the scripts module importable from the project root
# ---------------------------------------------------------------------------
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from remediate_cve import (  # noqa: E402
    _extract_cve_records,
    strip_markdown_fencing,
    validate_dockerfile_primitives,
    validate_dockerfile_instructions,
    write_patched_dockerfile,
    build_prompt,
    load_and_minimize_trivy_report,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SAMPLE_TRIVY_REPORT: dict = {
    "Results": [
        {
            "Target": "guardian-demo:latest (alpine 3.18.4)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "libssl",
                    "InstalledVersion": "3.1.0",
                    "FixedVersion": "3.1.5",
                    "Severity": "CRITICAL",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "libexpat",
                    "InstalledVersion": "2.5.0",
                    "FixedVersion": "2.6.0",
                    "Severity": "HIGH",
                },
                {
                    # Should be excluded — LOW severity
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "curl",
                    "InstalledVersion": "8.0.0",
                    "FixedVersion": "8.1.0",
                    "Severity": "LOW",
                },
                {
                    # Should be excluded — no fixed version yet
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.11",
                    "FixedVersion": "",
                    "Severity": "CRITICAL",
                },
            ],
        }
    ]
}

SAMPLE_DOCKERFILE = textwrap.dedent("""\
    FROM python:3.9-alpine
    WORKDIR /app
    COPY src/requirements.txt .
    RUN pip install -r requirements.txt
    COPY src/ .
    CMD ["python", "main.py"]
""")

PATCHED_DOCKERFILE = textwrap.dedent("""\
    FROM python:3.12-bookworm
    WORKDIR /app
    COPY src/requirements.txt .
    RUN pip install -r requirements.txt
    COPY src/ .
    CMD ["python", "main.py"]
""")


# ---------------------------------------------------------------------------
# 1. CVE Extraction & Minimization
# ---------------------------------------------------------------------------
class TestExtractCveRecords:
    def test_extracts_critical_and_high_only(self) -> None:
        records = _extract_cve_records(SAMPLE_TRIVY_REPORT)
        ids = [r["VulnerabilityID"] for r in records]
        assert "CVE-2024-1234" in ids
        assert "CVE-2024-5678" in ids

    def test_excludes_low_severity(self) -> None:
        records = _extract_cve_records(SAMPLE_TRIVY_REPORT)
        ids = [r["VulnerabilityID"] for r in records]
        assert "CVE-2024-0001" not in ids

    def test_excludes_unfixed_cves(self) -> None:
        records = _extract_cve_records(SAMPLE_TRIVY_REPORT)
        ids = [r["VulnerabilityID"] for r in records]
        assert "CVE-2024-9999" not in ids

    def test_only_four_keys_per_record(self) -> None:
        records = _extract_cve_records(SAMPLE_TRIVY_REPORT)
        expected_keys = {"VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion"}
        for record in records:
            assert set(record.keys()) == expected_keys

    def test_empty_results_returns_empty_list(self) -> None:
        assert _extract_cve_records({"Results": []}) == []

    def test_missing_results_key_returns_empty_list(self) -> None:
        assert _extract_cve_records({}) == []

    def test_null_vulnerabilities_handled(self) -> None:
        report = {"Results": [{"Target": "test", "Vulnerabilities": None}]}
        assert _extract_cve_records(report) == []


# ---------------------------------------------------------------------------
# 2. Markdown Fence Stripping
# ---------------------------------------------------------------------------
class TestStripMarkdownFencing:
    def test_strips_dockerfile_fence(self) -> None:
        raw = "```dockerfile\nFROM python:3.12\nCMD ['python']\n```"
        result = strip_markdown_fencing(raw)
        assert result.startswith("FROM")
        assert "```" not in result

    def test_strips_generic_fence(self) -> None:
        raw = "```\nFROM python:3.12\nCMD ['python']\n```"
        result = strip_markdown_fencing(raw)
        assert result.startswith("FROM")
        assert "```" not in result

    def test_strips_docker_fence(self) -> None:
        raw = "```docker\nFROM python:3.12\nCMD ['python']\n```"
        result = strip_markdown_fencing(raw)
        assert result.startswith("FROM")
        assert "```" not in result

    def test_no_fence_passthrough(self) -> None:
        raw = "FROM python:3.12\nCMD ['python']"
        result = strip_markdown_fencing(raw)
        assert result == raw

    def test_leading_fence_only(self) -> None:
        """Model was cut off before closing fence."""
        raw = "```dockerfile\nFROM python:3.12\nCMD ['python']"
        result = strip_markdown_fencing(raw)
        assert "```" not in result
        assert "FROM" in result

    def test_trailing_fence_only(self) -> None:
        raw = "FROM python:3.12\nCMD ['python']\n```"
        result = strip_markdown_fencing(raw)
        assert "```" not in result
        assert "FROM" in result

    def test_preserves_internal_content(self) -> None:
        inner = "FROM python:3.12\nWORKDIR /app\nCMD ['python', 'main.py']"
        raw = f"```dockerfile\n{inner}\n```"
        result = strip_markdown_fencing(raw)
        assert result == inner


# ---------------------------------------------------------------------------
# 3. Dockerfile Primitive Validation
# ---------------------------------------------------------------------------
class TestValidateDockerfilePrimitives:
    def test_valid_dockerfile_passes(self) -> None:
        # Should not raise or exit
        validate_dockerfile_primitives(PATCHED_DOCKERFILE)

    def test_missing_from_exits_1(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_primitives("WORKDIR /app\nCMD ['python']")
        assert exc_info.value.code == 1

    def test_missing_cmd_and_entrypoint_exits_1(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_primitives("FROM python:3.12\nWORKDIR /app")
        assert exc_info.value.code == 1

    def test_entrypoint_accepted_instead_of_cmd(self) -> None:
        content = "FROM python:3.12\nWORKDIR /app\nENTRYPOINT ['python', 'main.py']"
        validate_dockerfile_primitives(content)  # must not exit

    def test_both_cmd_and_entrypoint_passes(self) -> None:
        content = "FROM python:3.12\nENTRYPOINT ['python']\nCMD ['main.py']"
        validate_dockerfile_primitives(content)


# ---------------------------------------------------------------------------
# 4. Prompt Construction
# ---------------------------------------------------------------------------
class TestBuildPrompt:
    def test_prompt_contains_cve_report_tags(self) -> None:
        records = [{"VulnerabilityID": "CVE-2024-1234", "PkgName": "libssl",
                    "InstalledVersion": "3.1.0", "FixedVersion": "3.1.5"}]
        prompt = build_prompt(records, SAMPLE_DOCKERFILE)
        assert "[CVE_REPORT]" in prompt
        assert "[/CVE_REPORT]" in prompt

    def test_prompt_contains_dockerfile_tags(self) -> None:
        records = []
        prompt = build_prompt(records, SAMPLE_DOCKERFILE)
        assert "[CURRENT_DOCKERFILE]" in prompt
        assert "[/CURRENT_DOCKERFILE]" in prompt

    def test_prompt_ends_with_patch_cue(self) -> None:
        prompt = build_prompt([], SAMPLE_DOCKERFILE)
        assert prompt.strip().endswith("Patched Dockerfile:")

    def test_prompt_contains_cve_data(self) -> None:
        records = [{"VulnerabilityID": "CVE-2024-9999", "PkgName": "zlib",
                    "InstalledVersion": "1.2.11", "FixedVersion": "1.2.13"}]
        prompt = build_prompt(records, SAMPLE_DOCKERFILE)
        assert "CVE-2024-9999" in prompt
        assert "zlib" in prompt

    def test_prompt_contains_alpine_user_warning(self) -> None:
        """The hardened prompt must contain the CREATEGROUP anti-hallucination rule."""
        records = [{"VulnerabilityID": "CVE-2024-1234", "PkgName": "libssl",
                    "InstalledVersion": "3.1.0", "FixedVersion": "3.1.5"}]
        prompt = build_prompt(records, SAMPLE_DOCKERFILE)
        assert "CREATEGROUP" in prompt
        assert "ADDuser" in prompt
        assert "RUN addgroup" in prompt


# ---------------------------------------------------------------------------
# 5. Dockerfile Instruction Whitelist (Hallucination Defense)
# ---------------------------------------------------------------------------
class TestValidateDockerfileInstructions:
    def test_valid_dockerfile_passes(self) -> None:
        """A standard, well-formed Dockerfile should pass without error."""
        validate_dockerfile_instructions(PATCHED_DOCKERFILE)

    def test_hallucinated_creategroup_exits_1(self) -> None:
        """The exact hallucination from the bug report: CREATEGROUP."""
        hallucinated = "FROM python:3.12\nCREATEGROUP 1000 appgroup\nCMD ['python']"
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_instructions(hallucinated)
        assert exc_info.value.code == 1

    def test_hallucinated_adduser_with_capital_d_exits_1(self) -> None:
        """ADDuser (capital D) is not a Dockerfile instruction."""
        hallucinated = "FROM python:3.12\nADDuser -u 1000 appuser\nCMD ['python']"
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_instructions(hallucinated)
        assert exc_info.value.code == 1

    def test_hallucinated_install_exits_1(self) -> None:
        """INSTALL is not a Dockerfile instruction."""
        hallucinated = "FROM python:3.12\nINSTALL python3\nCMD ['python']"
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_instructions(hallucinated)
        assert exc_info.value.code == 1

    def test_hallucinated_groupadd_exits_1(self) -> None:
        """GROUPADD is a Linux command, not a Dockerfile instruction."""
        hallucinated = "FROM python:3.12\nGROUPADD appgroup\nCMD ['python']"
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_instructions(hallucinated)
        assert exc_info.value.code == 1

    def test_run_addgroup_passes(self) -> None:
        """addgroup under RUN is the CORRECT way — must pass."""
        valid = "FROM python:3.12\nRUN addgroup -g 1000 appgroup\nCMD ['python']"
        validate_dockerfile_instructions(valid)  # must not exit

    def test_comments_are_ignored(self) -> None:
        content = "# This is a comment\nFROM python:3.12\n# Another comment\nCMD ['python']"
        validate_dockerfile_instructions(content)

    def test_empty_lines_are_ignored(self) -> None:
        content = "FROM python:3.12\n\n\nCMD ['python']"
        validate_dockerfile_instructions(content)

    def test_continuation_lines_are_not_checked(self) -> None:
        """Lines after a backslash are continuation args, not instructions."""
        content = (
            "FROM python:3.12\n"
            "RUN addgroup -g 1000 appgroup \\\n"
            "    && adduser -u 1000 -G appgroup -D appuser\n"
            "CMD ['python']"
        )
        validate_dockerfile_instructions(content)  # must not exit

    def test_multiple_hallucinations_all_reported(self) -> None:
        """Multiple bad lines should all be caught."""
        content = "FROM python:3.12\nCREATEGROUP foo\nINSTALL bar\nCMD ['python']"
        with pytest.raises(SystemExit) as exc_info:
            validate_dockerfile_instructions(content)
        assert exc_info.value.code == 1

    def test_case_insensitive_instruction_matching(self) -> None:
        """Docker instructions are case-insensitive (from, From, FROM all valid)."""
        content = "from python:3.12\nworkdir /app\ncmd ['python']"
        validate_dockerfile_instructions(content)  # must not exit

    def test_full_realistic_dockerfile(self) -> None:
        """Our actual project Dockerfile structure should pass."""
        realistic = (
            "FROM python:3.12-slim\n"
            "LABEL maintainer='team@example.com'\n"
            "WORKDIR /app\n"
            "COPY src/requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY src/ .\n"
            "RUN addgroup -g 1000 appgroup \\\n"
            "    && adduser -u 1000 -G appgroup -s /bin/sh -D appuser \\\n"
            "    && chown -R appuser:appgroup /app\n"
            "USER appuser\n"
            "EXPOSE 8080\n"
            "HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://localhost:8080/healthz || exit 1\n"
            "CMD ['python', 'main.py']\n"
        )
        validate_dockerfile_instructions(realistic)


# ---------------------------------------------------------------------------
# 6. Side-by-Side File Write
# ---------------------------------------------------------------------------
class TestWritePatchedDockerfile:
    def test_writes_content_to_output_path(self, tmp_path: Path) -> None:
        original = tmp_path / "Dockerfile"
        output = tmp_path / "Dockerfile.patched"
        original.write_text(SAMPLE_DOCKERFILE)
        write_patched_dockerfile(output, PATCHED_DOCKERFILE, original_path=original)
        assert output.read_text() == PATCHED_DOCKERFILE

    def test_original_dockerfile_is_preserved(self, tmp_path: Path) -> None:
        """The original Dockerfile must NEVER be modified."""
        original = tmp_path / "Dockerfile"
        output = tmp_path / "Dockerfile.patched"
        original.write_text(SAMPLE_DOCKERFILE)
        write_patched_dockerfile(output, PATCHED_DOCKERFILE, original_path=original)
        assert original.read_text() == SAMPLE_DOCKERFILE  # UNCHANGED

    def test_tmp_file_cleaned_up_on_success(self, tmp_path: Path) -> None:
        original = tmp_path / "Dockerfile"
        output = tmp_path / "Dockerfile.patched"
        original.write_text(SAMPLE_DOCKERFILE)
        write_patched_dockerfile(output, PATCHED_DOCKERFILE, original_path=original)
        tmp_sibling = output.with_suffix(".tmp")
        assert not tmp_sibling.exists()

    def test_preserves_original_permissions(self, tmp_path: Path) -> None:
        original = tmp_path / "Dockerfile"
        output = tmp_path / "Dockerfile.patched"
        original.write_text(SAMPLE_DOCKERFILE)
        original_mode = original.stat().st_mode
        write_patched_dockerfile(output, PATCHED_DOCKERFILE, original_path=original)
        assert output.stat().st_mode == original_mode


# ---------------------------------------------------------------------------
# 6. Trivy Report Loader — file error handling
# ---------------------------------------------------------------------------
class TestLoadAndMinimizeTrivyReport:
    def test_missing_file_exits_1(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as exc_info:
            load_and_minimize_trivy_report(tmp_path / "nonexistent.json")
        assert exc_info.value.code == 1

    def test_malformed_json_exits_1(self, tmp_path: Path) -> None:
        bad = tmp_path / "trivy-results.json"
        bad.write_text("{not: valid json}")
        with pytest.raises(SystemExit) as exc_info:
            load_and_minimize_trivy_report(bad)
        assert exc_info.value.code == 1

    def test_valid_report_returns_records(self, tmp_path: Path) -> None:
        report_path = tmp_path / "trivy-results.json"
        report_path.write_text(json.dumps(SAMPLE_TRIVY_REPORT))
        records = load_and_minimize_trivy_report(report_path)
        assert len(records) == 2  # CRITICAL + HIGH, unfixed and LOW excluded
