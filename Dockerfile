# EthiScan Docker Image
# Ethical Web Vulnerability Scanner
#
# Build: docker build -t ethiscan .
# Run:   docker run --rm ethiscan scan --url https://example.com

FROM python:3.11-slim

# Set labels
LABEL maintainer="EthiScan Team"
LABEL description="Ethical Web Vulnerability Scanner"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd --gid 1000 ethiscan && \
    useradd --uid 1000 --gid ethiscan --shell /bin/bash --create-home ethiscan

# Set working directory
WORKDIR /app

# Install dependencies first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership to non-root user
RUN chown -R ethiscan:ethiscan /app

# Switch to non-root user
USER ethiscan

# Set entrypoint
ENTRYPOINT ["python", "-m", "ethiscan"]

# Default command (show help)
CMD ["--help"]
