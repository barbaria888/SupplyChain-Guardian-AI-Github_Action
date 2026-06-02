#!/usr/bin/env bash
# tests/integration/test_kind_deploy.sh — @SRE Domain
# =====================================================
# Validates that the patched Docker image deploys successfully inside
# the ephemeral KinD cluster and that all health gates pass.
#
# Called by the GitHub Actions 'validate' job after kubectl apply.
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
DIAGNOSTICS_DIR="kind-diagnostics"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
fail() {
    log "FAILURE: $*"
    collect_diagnostics "FAILED"
    exit 1
}

# ---------------------------------------------------------------------------
# Diagnostics Collection — called on failure AND success
# ---------------------------------------------------------------------------
collect_diagnostics() {
    local status="${1:-UNKNOWN}"
    log "Collecting cluster diagnostics (status=$status)..."
    mkdir -p "$DIAGNOSTICS_DIR"

    # Pod status
    kubectl get pods -n "$NAMESPACE" -l "app=$APP_NAME" -o wide \
        > "$DIAGNOSTICS_DIR/pod-status.txt" 2>&1 || true

    # Pod descriptions
    kubectl describe pods -n "$NAMESPACE" -l "app=$APP_NAME" \
        > "$DIAGNOSTICS_DIR/pod-describe.txt" 2>&1 || true

    # Pod logs (current)
    for pod in $(kubectl get pods -n "$NAMESPACE" -l "app=$APP_NAME" \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        kubectl logs "$pod" -n "$NAMESPACE" \
            > "$DIAGNOSTICS_DIR/logs-${pod}.txt" 2>&1 || true
        kubectl logs "$pod" -n "$NAMESPACE" --previous \
            > "$DIAGNOSTICS_DIR/logs-previous-${pod}.txt" 2>&1 || true
    done

    # Cluster events
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' \
        > "$DIAGNOSTICS_DIR/events.txt" 2>&1 || true

    # Deployment status
    kubectl get deployment "$APP_NAME" -n "$NAMESPACE" -o yaml \
        > "$DIAGNOSTICS_DIR/deployment-status.yaml" 2>&1 || true

    log "Diagnostics collected in $DIAGNOSTICS_DIR/"
}

# ---------------------------------------------------------------------------
# Gate 1: Deployment rollout
# ---------------------------------------------------------------------------
log "Gate 1 — Waiting for deployment/$APP_NAME to become available (timeout: $WAIT_TIMEOUT)..."
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
log "Gate 2 — Checking for CrashLoopBackOff or failed pods..."
CRASH_COUNT=$(kubectl get pods \
    -n "$NAMESPACE" \
    -l "app=$APP_NAME" \
    --no-headers \
    | grep -cE "CrashLoopBackOff|Error|OOMKilled|ImagePullBackOff" || true)

if [[ "$CRASH_COUNT" -gt 0 ]]; then
    fail "Found $CRASH_COUNT pod(s) in a failed state."
fi
log "Gate 2 PASSED — no crashed pods."

# ---------------------------------------------------------------------------
# Gate 3: Sustained running — pod must stay alive for ≥15 seconds
# ---------------------------------------------------------------------------
log "Gate 3 — Verifying pod remains running for 15 seconds..."
POD_NAME=$(kubectl get pods \
    -n "$NAMESPACE" \
    -l "app=$APP_NAME" \
    -o jsonpath='{.items[0].metadata.name}')

if [[ -z "$POD_NAME" ]]; then
    fail "No pods found for app=$APP_NAME."
fi

INITIAL_RESTARTS=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

log "Sleeping 15 seconds to verify sustained operation (initial restarts: $INITIAL_RESTARTS)..."
sleep 15

# Check pod is still Running (not Completed/CrashLoopBackOff)
POD_PHASE=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
FINAL_RESTARTS=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

if [[ "$POD_PHASE" != "Running" ]]; then
    fail "Pod exited during 15s stability window. Phase=$POD_PHASE (expected Running)."
fi

if [[ "$FINAL_RESTARTS" -gt "$INITIAL_RESTARTS" ]]; then
    fail "Pod restarted during 15s stability window. Restarts went from $INITIAL_RESTARTS to $FINAL_RESTARTS."
fi
log "Gate 3 PASSED — pod remained Running for 15 seconds with no restarts."

# ---------------------------------------------------------------------------
# Gate 4: Health probe response
# ---------------------------------------------------------------------------
log "Gate 4 — Running liveness probe check via kubectl exec..."
HEALTH_RESPONSE=$(kubectl exec "$POD_NAME" -n "$NAMESPACE" -- \
    python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/healthz').read().decode())" 2>/dev/null || echo "FAILED")

if echo "$HEALTH_RESPONSE" | grep -q '"status"'; then
    log "Gate 4 PASSED — /healthz returned ok."
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
    echo "--- Stability Window ---"
    echo "Pod phase after 15s: $POD_PHASE"
    echo "Restarts: $INITIAL_RESTARTS -> $FINAL_RESTARTS"
    echo ""
    echo "=== ALL GATES PASSED ==="
} > "$REPORT_FILE"

# Collect diagnostics on success too (for audit trail)
collect_diagnostics "PASSED"

log "Integration test PASSED. Report saved to $REPORT_FILE"
exit 0
