FROM python:3.11-slim

# Install build dependencies for coincurve (libsecp256k1)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libgmp-dev \
        libffi-dev \
        pkg-config \
        autoconf \
        automake \
        libtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./

# Create output directory
RUN mkdir -p /output

# Default environment variables
ENV KNOWN_WORDS=""
ENV NUM_WORKERS=""
ENV CHECK_API="true"
ENV ADDRESSES_PER_PATH="20"
ENV NETWORKS="liquid"
ENV OUTPUT_DIR="/output"
ENV API_WORKERS="8"
ENV API_RATE_LIMIT="0.05"
ENV RESUME_FROM="0"
ENV BIP39_PASSPHRASE=""

ENTRYPOINT ["python", "-u", "recover.py"]
