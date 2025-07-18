FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    tcpdump \
    net-tools \
    curl \
    wget \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/keys /app/logs /app/config

# Set proper permissions for packet capture
RUN setcap cap_net_raw,cap_net_admin=eip $(which python3) || true

# Create non-root user for security
RUN useradd -m -u 1001 wifimonitor && \
    chown -R wifimonitor:wifimonitor /app

# Switch to non-root user
USER wifimonitor

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Default command
CMD ["python3", "src/web_app.py"]