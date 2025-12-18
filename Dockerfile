FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    python3-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY shodan_monitor/ ./shodan_monitor
COPY scripts/ ./scripts

ENV PYTHONPATH=/app

CMD ["python3", "scripts/run_collector.py"]




