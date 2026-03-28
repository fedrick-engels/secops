# ── Stage 1: Builder ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into a separate folder for copying
COPY app/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Production Image ─────────────────────────────────────
FROM python:3.12-slim AS production

# Security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ .

# Set ownership
RUN chown -R appuser:appgroup /app

# Drop to non-root
USER appuser

# Expose app port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run with gunicorn (production WSGI server)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", \
     "--timeout", "60", "--access-logfile", "-", "main:app"]
