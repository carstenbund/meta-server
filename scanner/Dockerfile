# scanner/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/scanner
COPY __init__.py scan_service.py /app/scanner/

ENV PYTHONPATH=/app
CMD ["python", "-m", "scanner.scan_service"]
