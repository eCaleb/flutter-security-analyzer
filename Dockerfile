# Flutter Security Scanner - Docker Container
#
# Multi-stage build for a minimal, secure container that runs
# the scanner against mounted Flutter project directories.
#
# Usage:
#   Build:  docker build -t flutter-security-scanner .
#   Scan:   docker run -v /path/to/flutter/project:/scan flutter-security-scanner /scan
#   JSON:   docker run -v /path/to/project:/scan -v /path/to/output:/output flutter-security-scanner /scan -f json -o /output/results.json
#   HTML:   docker run -v /path/to/project:/scan -v /path/to/output:/output flutter-security-scanner /scan -f html -o /output/report.html
#
# Author: Caleb Elebhose
# Module: WB7103/WB7104 MSc Cybersecurity Project
# University of Chester

# ---- Stage 1: Test runner ----
# Runs unit tests to verify the scanner works before building the final image
FROM python:3.12-slim AS test

WORKDIR /app

# Copy source and test files
COPY src/ ./src/
COPY tests/ ./tests/
COPY samples/ ./samples/
COPY requirements.txt .

# Install test dependencies and run tests
RUN pip install --no-cache-dir pytest && \
    python -m pytest tests/ -v --tb=short

# ---- Stage 2: Production image ----
# Minimal image with only the scanner code (no test dependencies)
FROM python:3.12-slim AS production

# Security: run as non-root user
RUN groupadd -r scanner && useradd -r -g scanner -d /app -s /sbin/nologin scanner

WORKDIR /app

# Copy only the scanner source code (no tests, no dev dependencies)
COPY --from=test /app/src/ ./src/
COPY --from=test /app/samples/ ./samples/

# Set ownership
RUN chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Scanner entry point
# The /scan directory is where users mount their Flutter project
ENTRYPOINT ["python", "src/main.py"]

# Default: show help if no arguments provided
CMD ["--help"]

# Labels for container metadata
LABEL maintainer="Caleb Elebhose <caleb.elebhose@chester.ac.uk>"
LABEL description="Flutter Security Scanner - SAST tool for Dart/Flutter with MASVS v2.1.0 mapping"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/calebelebhose/flutter-security-scanner"
