#!/usr/bin/env bash
# =============================================================================
# scripts/preflight_docker.sh — Docker Build Preflight Validator
# =============================================================================
# Validates all prerequisites before a `docker build` to catch path errors
# early with clear, actionable messages — instead of cryptic Docker lstat
# failures.
#
# Usage:
#   bash preflight_docker.sh <dockerfile_path> <build_context_path>
#
# Validates:
#   1. Dockerfile exists and is readable
#   2. Build context directory exists
#   3. COPY/ADD source paths referenced in the Dockerfile exist
#   4. Logs a diagnostic tree of the build context
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more validation errors detected
#
# Owner: @SRE
# =============================================================================
set -euo pipefail

DOCKERFILE="${1:?Usage: preflight_docker.sh <dockerfile> <build_context>}"
BUILD_CONTEXT="${2:?Usage: preflight_docker.sh <dockerfile> <build_context>}"

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
echo "═══════════════════════════════════════════════════════════════"
echo "  Docker Build Preflight Validation"
echo "═══════════════════════════════════════════════════════════════"
echo "  Dockerfile      : $DOCKERFILE"
echo "  Build context   : $BUILD_CONTEXT"
echo "  Working dir     : $(pwd)"
echo "  Date            : $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

ERRORS=0

# ---------------------------------------------------------------------------
# Check 1 — Dockerfile exists and is readable
# ---------------------------------------------------------------------------
if [[ ! -f "$DOCKERFILE" ]]; then
  echo "::error::PREFLIGHT FAIL — Dockerfile not found: $DOCKERFILE"
  echo "  Hint: Verify the 'dockerfile' input or DOCKERFILE_PATH variable."
  ERRORS=$((ERRORS + 1))
elif [[ ! -r "$DOCKERFILE" ]]; then
  echo "::error::PREFLIGHT FAIL — Dockerfile not readable: $DOCKERFILE"
  ERRORS=$((ERRORS + 1))
else
  LINE_COUNT=$(wc -l < "$DOCKERFILE" | tr -d ' ')
  BYTE_COUNT=$(wc -c < "$DOCKERFILE" | tr -d ' ')
  echo "  ✓ Dockerfile exists: $DOCKERFILE ($LINE_COUNT lines, $BYTE_COUNT bytes)"
fi

# ---------------------------------------------------------------------------
# Check 2 — Build context directory exists
# ---------------------------------------------------------------------------
if [[ ! -d "$BUILD_CONTEXT" ]]; then
  echo "::error::PREFLIGHT FAIL — Build context directory not found: $BUILD_CONTEXT"
  echo "  Hint: Ensure the repository is checked out and the path is correct."
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Build context exists: $BUILD_CONTEXT"
fi

# ---------------------------------------------------------------------------
# Check 3 — Log build context tree (depth 2, exclude .git)
# ---------------------------------------------------------------------------
echo ""
echo "  Build context tree (depth 2):"
echo "  ─────────────────────────────"
if command -v tree &>/dev/null; then
  tree -L 2 --charset=ascii -I '.git' "$BUILD_CONTEXT" 2>/dev/null | head -60 || true
else
  find "$BUILD_CONTEXT" -maxdepth 2 \
    -not -path '*/.git/*' -not -path '*/.git' \
    -print 2>/dev/null | sort | head -60 || true
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4 — Validate COPY/ADD source paths exist in build context
# ---------------------------------------------------------------------------
if [[ -f "$DOCKERFILE" && -d "$BUILD_CONTEXT" ]]; then
  echo "  Validating COPY/ADD source paths..."
  echo "  ────────────────────────────────────"

  # Track errors inside the loop via a temp file (subshell-safe).
  COPY_ERRORS_FILE=$(mktemp)
  echo "0" > "$COPY_ERRORS_FILE"

  # Parse COPY/ADD lines, handling multi-line continuations.
  # We join continuation lines (ending with \) into single logical lines first.
  sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' "$DOCKERFILE" | \
    grep -iE '^\s*(COPY|ADD)\s' 2>/dev/null | \
    while IFS= read -r line; do

    # Skip multi-stage COPY --from=<stage>
    if echo "$line" | grep -qiE '\-\-from='; then
      echo "    ⊘ Skipping multi-stage: $(echo "$line" | head -c 80)"
      continue
    fi

    # Remove known flags: --chown=..., --chmod=..., --link, --exclude=...
    cleaned=$(echo "$line" | sed -E 's/--[a-zA-Z]+=("[^"]*"|[^ ]*)\s*//g; s/--[a-zA-Z]+\s*//g')

    # Extract instruction and arguments
    instruction=$(echo "$cleaned" | awk '{print toupper($1)}')
    # Collect all arguments after the instruction
    args=()
    while IFS= read -r arg; do
      [[ -n "$arg" ]] && args+=("$arg")
    done < <(echo "$cleaned" | awk '{for(i=2;i<=NF;i++) print $i}')

    # Need at least 2 args (source + destination)
    if [[ ${#args[@]} -lt 2 ]]; then
      continue
    fi

    # All args except the last one are sources
    for ((i=0; i<${#args[@]}-1; i++)); do
      src="${args[$i]}"

      # Skip URLs (ADD supports remote URLs)
      if [[ "$src" =~ ^https?:// ]]; then
        echo "    ⊘ Skipping URL source: $src"
        continue
      fi

      # Skip root-anchored absolute paths (e.g., COPY /etc/something)
      if [[ "$src" = /* ]]; then
        echo "    ⊘ Skipping absolute path: $src"
        continue
      fi

      # Resolve path relative to build context
      # Handle glob patterns: check if any match exists
      full_path="$BUILD_CONTEXT/$src"
      # Use ls to test glob expansion
      if ! ls -d $full_path &>/dev/null 2>&1; then
        echo "::error::PREFLIGHT FAIL — $instruction source not found: '$src' (expected at: $full_path)"
        echo "  Hint: Check for typos in your Dockerfile. Is '$src' the correct path?"
        current=$(cat "$COPY_ERRORS_FILE")
        echo $((current + 1)) > "$COPY_ERRORS_FILE"
      else
        echo "    ✓ $instruction source exists: $src"
      fi
    done
  done

  COPY_ERR_COUNT=$(cat "$COPY_ERRORS_FILE" 2>/dev/null || echo "0")
  rm -f "$COPY_ERRORS_FILE"
  ERRORS=$((ERRORS + COPY_ERR_COUNT))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ $ERRORS -gt 0 ]]; then
  echo "  ✗ PREFLIGHT FAILED — $ERRORS error(s) detected."
  echo "    Docker build will not succeed with the current configuration."
  echo "    Review the errors above and fix path references in your Dockerfile."
  echo "═══════════════════════════════════════════════════════════════"
  exit 1
fi

echo "  ✓ All preflight checks passed. Proceeding with docker build."
echo "═══════════════════════════════════════════════════════════════"
exit 0
