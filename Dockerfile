FROM python:3.12-slim

LABEL maintainer="OwlScan Community"
LABEL description="OwlScan OSINT Framework — Phantom Signal"
LABEL version="1.0.0"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    nmap dnsutils whois curl \
    chromium chromium-driver \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install playwright browsers
RUN playwright install chromium --with-deps 2>/dev/null || true

# Copy application code
COPY . .
RUN pip install --no-cache-dir -e .

# Initialize database
RUN python -c "from owlscan.core.database import init_db; init_db()"

# Create exports directory
RUN mkdir -p /app/exports /app/data

EXPOSE 5000

ENV OWLSCAN_HOST=0.0.0.0
ENV OWLSCAN_PORT=5000
ENV OWLSCAN_DB_URL=sqlite:////app/data/owlscan.db

VOLUME ["/app/data", "/app/exports"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

CMD ["python", "run.py"]
