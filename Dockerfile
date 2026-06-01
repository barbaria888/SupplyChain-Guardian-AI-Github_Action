# ⚠️  INTENTIONALLY VULNERABLE BASE IMAGE — PIPELINE TEST FIXTURE ⚠️
#
# This Dockerfile uses python:3.9-alpine which contains multiple known CVEs
# (e.g., outdated OpenSSL, libexpat, and setuptools versions).
# It is the BEFORE state that the Supply Chain Guardian pipeline will detect
# and automatically patch to a safe, current base image.
#
# DO NOT update this file manually. Let the pipeline demonstrate the fix.
# ---------------------------------------------------------------------------

FROM python:3.9-alpine

# Metadata
LABEL maintainer="platform-team@example.com"
LABEL guardian.dev/cve-status="vulnerable"
LABEL guardian.dev/baseline="true"

# Set working directory
WORKDIR /app

# Install dependencies
# Pinned to an older pip version to simulate a real supply-chain vulnerability
COPY src/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==23.0 \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ .

# Create a non-root user
# Even in the vulnerable version, we practice least-privilege
RUN addgroup -g 1000 appgroup \
    && adduser -u 1000 -G appgroup -s /bin/sh -D appuser \
    && chown -R appuser:appgroup /app

USER appuser

# Expose service port
EXPOSE 8080

# Health check at the Docker layer (supplements K8s probes)
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

# Run the application
CMD ["python", "main.py"]
