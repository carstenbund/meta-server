# indexer/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/indexer
COPY __init__.py index_worker.py topic_resolver.py topic_maintenance.py /app/indexer/

ENV PYTHONPATH=/app
CMD ["python", "-m", "indexer.index_worker"]
