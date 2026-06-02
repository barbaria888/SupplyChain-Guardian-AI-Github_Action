#!/usr/bin/env bash
# scripts/validate_image.sh — @SRE + @AIPatcher Domain
# =======================================================
# Production-grade post-build image validation gate.
#
# Validates that the AI-patched Docker image is genuinely safe to promote:
#   1. USER existence   — declared USER must exist in /etc/passwd
#   2. USER regression  — USER/WORKDIR/CMD/ENTRYPOINT unchanged vs baseline
#   3. WORKDIR exists   — declared working directory exists inside container
#   4. Runtime stability — container stays alive ≥15s with no restarts
#   5. Health probe     — /healthz returns HTTP 200
#
# All results are appended to AUDIT_LOG (default: patch_audit.log).
# On failure, forensic data (logs, inspect, history) is written to
# FORENSICS_DIR (default: runtime-failure-report/).
#
# Environment variables:
#   PATCHED_IMAGE     — image tag to validate (required)
#   BASELINE_IMAGE    — original image tag for regression check (required)
#   HEALTHZ_PORT      — host port mapped to container's 8080 (default: 18080)
#   HEALTHZ_PATH      — health endpoint path (default: /healthz)
#   STABILITY_SECONDS — how long container must stay alive (default: 15)
#   AUDIT_LOG         — path to append audit entries (default: patch_audit.log)
#   FORENSICS_DIR     — directory to write failure forensics (default: runtime-failure-report)
#
# Exit: 0 = all gates PASSED, 1 = any gate FAILED

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PATCHED_IMAGE="${PATCHED_IMAGE:?PATCHED_IMAGE is required}"
BASELINE_IMAGE="${BASELINE_IMAGE:?BASELINE_IMAGE is required}"
HEALTHZ_PORT="${HEALTHZ_PORT:-18080}"
HEALTHZ_PATH="${HEALTHZ_PATH:-/healthz}"
STABILITY_SECONDS="${STABILITY_SECONDS:-15}"
AUDIT_LOG="${AUDIT_LOG:-patch_audit.log}"
FORENSICS_DIR="${FORENSICS_DIR:-runtime-failure-report}"

CTR="guardian-validate-$$"
OVERALL_PASS=true

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
pass() {
    local gate="$1"; shift
    log "[PASS] $gate"
    printf '[PASS] %s\n%s\n\n' "$gate" "$*" >> "$AUDIT_LOG"
}
fail() {
    local gate="$1"; shift
    log "[FAIL] $gate"
    log "       $*"
    printf '[FAIL] %s\n%s\n\n' "$gate" "$*" >> "$AUDIT_LOG"
    OVERALL_PASS=false
}

collect_forensics() {
    log "Collecting failure forensics into $FORENSICS_DIR/ ..."
    mkdir -p "$FORENSICS_DIR"

    # Container logs (best effort — container may not exist)
    docker logs "$CTR" > "$FORENSICS_DIR/container-logs.txt" 2>&1 || true
    docker inspect "$CTR" > "$FORENSICS_DIR/container-inspect.json" 2>&1 || true

    # Image-level forensics
    docker inspect "$PATCHED_IMAGE" > "$FORENSICS_DIR/image-inspect.json" 2>&1 || true
    docker history --no-trunc "$PATCHED_IMAGE" > "$FORENSICS_DIR/image-history.txt" 2>&1 || true

    log "Forensics written to $FORENSICS_DIR/"
}

# ---------------------------------------------------------------------------
# Gate 1 — USER Existence
# Verify that the user declared in .Config.User actually exists in /etc/passwd.
# ---------------------------------------------------------------------------
log "=== Gate 1: USER Existence ==="
IMG_USER=$(docker inspect "$PATCHED_IMAGE" --format='{{.Config.User}}' 2>/dev/null || true)
log "Declared USER in image: '${IMG_USER:-<none>}'"

if [[ -n "$IMG_USER" ]]; then
    # Strip UID:GID notation — we only care about the user name/UID portion
    USER_NAME="${IMG_USER%%:*}"

    # Run a one-shot container to check /etc/passwd
    PASSWD_CHECK=$(docker run --rm --entrypoint="" "$PATCHED_IMAGE" \
        sh -c "getent passwd '${USER_NAME}' || grep -w '${USER_NAME}' /etc/passwd" 2>/dev/null || true)

    if [[ -z "$PASSWD_CHECK" ]]; then
        fail "User Existence Validation" \
             "USER: ${USER_NAME}\nNot found in /etc/passwd — user was not created (adduser/useradd missing from Dockerfile)"
    else
        pass "User Existence Validation" \
             "USER: ${USER_NAME}\nPasswd entry: ${PASSWD_CHECK}"
    fi
else
    log "[INFO] No USER declared in image — skipping existence check."
    printf '[INFO] User Existence Validation\nNo USER set in image config — skipped.\n\n' >> "$AUDIT_LOG"
fi

# ---------------------------------------------------------------------------
# Gate 2 — Regression Check (USER / WORKDIR / CMD / ENTRYPOINT)
# ---------------------------------------------------------------------------
log "=== Gate 2: Regression Check vs Baseline ==="

inspect_field() {
    local img="$1" field="$2"
    docker inspect "$img" --format="{{json ${field}}}" 2>/dev/null || echo "null"
}

ORIG_USER=$(inspect_field "$BASELINE_IMAGE"  '.Config.User')
PATCH_USER=$(inspect_field "$PATCHED_IMAGE"  '.Config.User')
ORIG_WORKDIR=$(inspect_field "$BASELINE_IMAGE"  '.Config.WorkingDir')
PATCH_WORKDIR=$(inspect_field "$PATCHED_IMAGE"  '.Config.WorkingDir')
ORIG_CMD=$(inspect_field "$BASELINE_IMAGE"   '.Config.Cmd')
PATCH_CMD=$(inspect_field "$PATCHED_IMAGE"   '.Config.Cmd')
ORIG_EP=$(inspect_field "$BASELINE_IMAGE"    '.Config.Entrypoint')
PATCH_EP=$(inspect_field "$PATCHED_IMAGE"    '.Config.Entrypoint')

REGRESSION_DIFF=""
check_field() {
    local field="$1" orig="$2" patched="$3"
    if [[ "$orig" != "$patched" ]]; then
        local line="  $field: ${orig} → ${patched}"
        log "::error::REGRESSION — $line"
        REGRESSION_DIFF="${REGRESSION_DIFF}\n${line}"
    fi
}

check_field "USER"        "$ORIG_USER"    "$PATCH_USER"
check_field "WORKDIR"     "$ORIG_WORKDIR" "$PATCH_WORKDIR"
check_field "CMD"         "$ORIG_CMD"     "$PATCH_CMD"
check_field "ENTRYPOINT"  "$ORIG_EP"      "$PATCH_EP"

REGRESSION_REPORT="Baseline vs Patched comparison:"
REGRESSION_REPORT="${REGRESSION_REPORT}\n  USER:        ${ORIG_USER} → ${PATCH_USER}"
REGRESSION_REPORT="${REGRESSION_REPORT}\n  WORKDIR:     ${ORIG_WORKDIR} → ${PATCH_WORKDIR}"
REGRESSION_REPORT="${REGRESSION_REPORT}\n  CMD:         ${ORIG_CMD} → ${PATCH_CMD}"
REGRESSION_REPORT="${REGRESSION_REPORT}\n  ENTRYPOINT:  ${ORIG_EP} → ${PATCH_EP}"

if [[ -n "$REGRESSION_DIFF" ]]; then
    fail "Regression Gate" "${REGRESSION_REPORT}\n\nDIFF:${REGRESSION_DIFF}"
else
    pass "Regression Gate" "${REGRESSION_REPORT}\n\nAll runtime fields unchanged."
fi

# ---------------------------------------------------------------------------
# Gate 3 — WORKDIR Exists Inside Container
# ---------------------------------------------------------------------------
log "=== Gate 3: WORKDIR Exists in Container ==="
WORKDIR_VAL=$(docker inspect "$PATCHED_IMAGE" --format='{{.Config.WorkingDir}}' 2>/dev/null || true)

if [[ -z "$WORKDIR_VAL" || "$WORKDIR_VAL" == '""' ]]; then
    fail "WORKDIR Validation" "WORKDIR: <empty>\nNo WorkingDir set in image config."
else
    # Check the directory actually exists inside the image
    DIR_EXISTS=$(docker run --rm --entrypoint="" "$PATCHED_IMAGE" \
        sh -c "test -d '${WORKDIR_VAL}' && echo yes || echo no" 2>/dev/null || echo "no")

    if [[ "$DIR_EXISTS" != "yes" ]]; then
        fail "WORKDIR Validation" \
             "WORKDIR: ${WORKDIR_VAL}\nDirectory does not exist inside container filesystem."
    else
        pass "WORKDIR Validation" "WORKDIR: ${WORKDIR_VAL}\nDirectory exists inside container."
    fi
fi

# ---------------------------------------------------------------------------
# Gate 4 — Runtime Stability (≥15s alive, no restarts, exit-code absent)
# ---------------------------------------------------------------------------
log "=== Gate 4: Runtime Stability (${STABILITY_SECONDS}s window) ==="

docker run -d --name "$CTR" -p "${HEALTHZ_PORT}:8080" "$PATCHED_IMAGE"
log "Container started: $CTR"

INITIAL_RESTARTS=$(docker inspect "$CTR" --format='{{.RestartCount}}' 2>/dev/null || echo "0")
log "Sleeping ${STABILITY_SECONDS}s for stability check (initial restarts: $INITIAL_RESTARTS)..."
sleep "$STABILITY_SECONDS"

RUNNING=$(docker inspect "$CTR" --format='{{.State.Running}}' 2>/dev/null || echo "false")
EXIT_CODE=$(docker inspect "$CTR" --format='{{.State.ExitCode}}' 2>/dev/null || echo "-1")
FINAL_RESTARTS=$(docker inspect "$CTR" --format='{{.RestartCount}}' 2>/dev/null || echo "0")
STATUS=$(docker inspect "$CTR" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")

if [[ "$RUNNING" != "true" ]]; then
    RUNTIME_MSG="Container exited during ${STABILITY_SECONDS}s window.\nStatus=${STATUS} ExitCode=${EXIT_CODE} Restarts=${FINAL_RESTARTS}"
    fail "Runtime Stability" "$RUNTIME_MSG"
    collect_forensics
    docker rm -f "$CTR" 2>/dev/null || true
elif [[ "$FINAL_RESTARTS" -gt "$INITIAL_RESTARTS" ]]; then
    RUNTIME_MSG="Container restarted during ${STABILITY_SECONDS}s window.\nRestarts: ${INITIAL_RESTARTS} → ${FINAL_RESTARTS}"
    fail "Runtime Stability" "$RUNTIME_MSG"
    collect_forensics
    docker rm -f "$CTR" 2>/dev/null || true
else
    pass "Runtime Stability" \
         "Container alive for ${STABILITY_SECONDS}s.\nStatus=running ExitCode=none Restarts=${FINAL_RESTARTS}"
fi

# ---------------------------------------------------------------------------
# Gate 5 — Health Endpoint
# ---------------------------------------------------------------------------
log "=== Gate 5: Health Probe (${HEALTHZ_PATH}) ==="

HEALTH_OK=false
HEALTH_RESP=""
for i in $(seq 1 6); do
    HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' \
        "http://localhost:${HEALTHZ_PORT}${HEALTHZ_PATH}" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        HEALTH_RESP=$(curl -sf "http://localhost:${HEALTHZ_PORT}${HEALTHZ_PATH}" 2>/dev/null || true)
        HEALTH_OK=true
        break
    fi
    log "  Attempt $i — HTTP $HTTP_CODE, retrying in 2s..."
    sleep 2
done

# Collect container logs regardless of health outcome
docker logs "$CTR" > runtime-smoke-logs.txt 2>&1 || true
docker rm -f "$CTR" 2>/dev/null || true

if [[ "$HEALTH_OK" != "true" ]]; then
    fail "Health Probe" "GET ${HEALTHZ_PATH} did not return HTTP 200 after 6 attempts."
    collect_forensics
else
    pass "Health Probe" "GET ${HEALTHZ_PATH} → HTTP 200\nResponse: ${HEALTH_RESP}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log ""
log "=== Validation Summary ==="
grep -E '^\[(PASS|FAIL|INFO)\]' "$AUDIT_LOG" | tail -20 || true

if [[ "$OVERALL_PASS" != "true" ]]; then
    log ""
    log "::error::Image validation FAILED — one or more gates did not pass."
    log "::error::Review $AUDIT_LOG and $FORENSICS_DIR/ for details."
    exit 1
fi

log ""
log "All validation gates PASSED."
exit 0
