# Use a slim version of Python for a smaller image footprint
FROM python:3.11-slim

# Build-time arguments for multi-platform support
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Set shell for better error handling
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /app

# Install system dependencies
# libpq-dev is required for psycopg2, gcc and python3-dev for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
# --no-cache-dir reduces image size
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application structure
# Updated: apex_forge instead of shodan_monitor
COPY apex_forge/ ./apex_forge/
COPY scripts/ ./scripts/
COPY profiles.yaml ./profiles.yaml

# Set Python path to ensure module imports work correctly
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Security: Create and use a non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check verifies the python environment and core dependencies are functional
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import psycopg2; import pymongo; import pydantic; sys.exit(0)" || exit 1

# Start the collector
CMD ["python", "scripts/run_collector.py"]



