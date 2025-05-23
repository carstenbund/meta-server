# indexer/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libmagic1 && \
    pip install --no-cache-dir \
        sqlalchemy \
        requests \
        python-magic \
        tika \
        langdetect \
        pefile

COPY index_worker.py .
COPY ../MyLogger.py .

CMD ["python", "index_worker.py"]

