#!/usr/bin/env bash
# =============================================================================
# scripts/preflight_docker.sh — Docker Build Preflight Validator
# =============================================================================
# Validates prerequisites before `docker build` so path errors surface early
# with clear messages instead of cryptic Docker lstat failures.
#
# Usage:
#   bash preflight_docker.sh <dockerfile_path> [build_context_path]
#
# If build_context is omitted, it's derived from the Dockerfile location:
#   ./backend/Dockerfile → context = ./backend
#   ./Dockerfile          → context = .
#
# Reads POLICY_PRESET env var (strict/lax):
#   strict (default) → exit 1 on any error
#   lax              → warn and exit 0
#
# Owner: @SRE
# =============================================================================
set -euo pipefail

DOCKERFILE="${1:?Usage: preflight_docker.sh <dockerfile> [build_context]}"

# --- Universal context derivation ---
# If $2 is provided, use it. Otherwise, figure it out from the Dockerfile path.
if [[ -n "${2:-}" ]]; then
  BUILD_CONTEXT="$2"
else
  # ./backend/Dockerfile → ./backend | ./Dockerfile → .
  BUILD_CONTEXT="$(dirname "$DOCKERFILE")"
  [[ "$BUILD_CONTEXT" == "." ]] || true
fi

POLICY="${POLICY_PRESET:-strict}"
ERRORS=0

echo "═══════════════════════════════════════════════════════════════"
echo "  Docker Build Preflight"
echo "═══════════════════════════════════════════════════════════════"
echo "  Dockerfile    : $DOCKERFILE"
echo "  Build context : $BUILD_CONTEXT"
echo "  Policy        : $POLICY"
echo "═══════════════════════════════════════════════════════════════"

# --- Check 1: Dockerfile exists ---
if [[ ! -f "$DOCKERFILE" ]]; then
  echo "::error::PREFLIGHT FAIL — Dockerfile not found: $DOCKERFILE"
  ERRORS=$((ERRORS + 1))
elif [[ ! -r "$DOCKERFILE" ]]; then
  echo "::error::PREFLIGHT FAIL — Dockerfile not readable: $DOCKERFILE"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Dockerfile exists ($(wc -l < "$DOCKERFILE" | tr -d ' ') lines)"
fi

# --- Check 2: Build context exists ---
if [[ ! -d "$BUILD_CONTEXT" ]]; then
  echo "::error::PREFLIGHT FAIL — Build context not found: $BUILD_CONTEXT"
  ERRORS=$((ERRORS + 1))
else
  echo "  ✓ Build context exists: $BUILD_CONTEXT"
fi

# --- Check 3: Validate COPY/ADD sources ---
if [[ -f "$DOCKERFILE" && -d "$BUILD_CONTEXT" ]]; then
  echo ""
  echo "  Checking COPY/ADD source paths..."
  # Join continuation lines, then grep for COPY/ADD
  sed -e ':a' -e '/\\$/N; s/\\\n/ /; ta' "$DOCKERFILE" | \
    grep -iE '^\s*(COPY|ADD)\s' 2>/dev/null | \
    while IFS= read -r line; do
      # Skip multi-stage COPY --from=
      echo "$line" | grep -qiE '\-\-from=' && continue

      # Remove flags like --chown=, --chmod=, --link
      cleaned=$(echo "$line" | sed -E 's/--[a-zA-Z]+=("[^"]*"|[^ ]*)\s*//g; s/--[a-zA-Z]+\s*//g')

      # Parse: INSTRUCTION src1 src2 ... dest
      args=()
      while IFS= read -r arg; do
        [[ -n "$arg" ]] && args+=("$arg")
      done < <(echo "$cleaned" | awk '{for(i=2;i<=NF;i++) print $i}')

      [[ ${#args[@]} -lt 2 ]] && continue

      # Check each source (everything except the last arg which is dest)
      for ((i=0; i<${#args[@]}-1; i++)); do
        src="${args[$i]}"
        # Skip URLs and absolute paths
        [[ "$src" =~ ^https?:// || "$src" = /* ]] && continue
        if ! ls -d "$BUILD_CONTEXT/$src" &>/dev/null 2>&1; then
          echo "::error::PREFLIGHT FAIL — source not found: '$src'"
          ERRORS=$((ERRORS + 1))
        else
          echo "    ✓ $src"
        fi
      done
    done
fi

# --- Summary ---
echo ""
echo "═══════════════════════════════════════════════════════════════"
if [[ $ERRORS -gt 0 ]]; then
  if [[ "$POLICY" == "lax" ]]; then
    echo "  ⚠ PREFLIGHT: $ERRORS error(s) detected, but policy=lax. Continuing."
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
  else
    echo "  ✗ PREFLIGHT FAILED — $ERRORS error(s). Fix paths in your Dockerfile."
    echo "═══════════════════════════════════════════════════════════════"
    exit 1
  fi
fi

echo "  ✓ All preflight checks passed."
echo "═══════════════════════════════════════════════════════════════"
exit 0
