#!/usr/bin/env bash
# tests/integration/test_kind_deploy.sh — @SRE Domain
# =====================================================
# Validates that the patched Docker image deploys successfully inside
# the ephemeral KinD cluster and that all health gates pass.
#
# Called by the GitHub Actions 'verify' job after kubectl apply.
# Exits 0 on success, 1 on any failure.
#
# Required environment variables:
#   IMAGE_TAG    — the fully qualified image tag loaded into KinD
#   NAMESPACE    — Kubernetes namespace (default: "default")
#   APP_NAME     — Deployment name (default: "guardian-demo")
#   WAIT_TIMEOUT — kubectl wait timeout (default: "90s")

set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-guardian-demo:patched}"
NAMESPACE="${NAMESPACE:-default}"
APP_NAME="${APP_NAME:-guardian-demo}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-90s}"
REPORT_FILE="kind-test-report.txt"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
fail() { log "FAILURE: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Gate 1: Deployment rollout
# ---------------------------------------------------------------------------
log "Waiting for deployment/$APP_NAME to become available (timeout: $WAIT_TIMEOUT)..."
if ! kubectl wait \
    --for=condition=available \
    --timeout="$WAIT_TIMEOUT" \
    deployment/"$APP_NAME" \
    -n "$NAMESPACE"; then
    fail "Deployment did not reach Available state within $WAIT_TIMEOUT."
fi
log "Gate 1 PASSED — deployment is Available."

# ---------------------------------------------------------------------------
# Gate 2: All pods Running (no CrashLoopBackOff)
# ---------------------------------------------------------------------------
log "Checking for CrashLoopBackOff or failed pods..."
CRASH_COUNT=$(kubectl get pods \
    -n "$NAMESPACE" \
    -l "app=$APP_NAME" \
    --no-headers \
    | grep -cE "CrashLoopBackOff|Error|OOMKilled|ImagePullBackOff" || true)

if [[ "$CRASH_COUNT" -gt 0 ]]; then
    kubectl describe pods -n "$NAMESPACE" -l "app=$APP_NAME"
    fail "Found $CRASH_COUNT pod(s) in a failed state."
fi
log "Gate 2 PASSED — no crashed pods."

# ---------------------------------------------------------------------------
# Gate 3: Health probe response
# ---------------------------------------------------------------------------
log "Running liveness probe check via kubectl exec..."
POD_NAME=$(kubectl get pods \
    -n "$NAMESPACE" \
    -l "app=$APP_NAME" \
    -o jsonpath='{.items[0].metadata.name}')

if [[ -z "$POD_NAME" ]]; then
    fail "No pods found for app=$APP_NAME."
fi

HEALTH_RESPONSE=$(kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
    wget -qO- http://localhost:8080/healthz 2>/dev/null || echo "FAILED")

if echo "$HEALTH_RESPONSE" | grep -q '"status": *"ok"'; then
    log "Gate 3 PASSED — /healthz returned ok."
else
    fail "Health probe returned unexpected response: $HEALTH_RESPONSE"
fi

# ---------------------------------------------------------------------------
# Generate test report artifact
# ---------------------------------------------------------------------------
log "Generating cluster test report: $REPORT_FILE"
{
    echo "=== Supply Chain Guardian — KinD Integration Test Report ==="
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Image: $IMAGE_TAG"
    echo "Namespace: $NAMESPACE"
    echo ""
    echo "--- Pod Status ---"
    kubectl get pods -n "$NAMESPACE" -l "app=$APP_NAME" -o wide
    echo ""
    echo "--- Deployment Description ---"
    kubectl describe deployment/"$APP_NAME" -n "$NAMESPACE"
    echo ""
    echo "--- Recent Events ---"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20
    echo ""
    echo "--- Health Probe Response ---"
    echo "$HEALTH_RESPONSE"
    echo ""
    echo "=== ALL GATES PASSED ==="
} > "$REPORT_FILE"

log "Integration test PASSED. Report saved to $REPORT_FILE"
exit 0
