# scanner/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libmagic1 && \
    pip install --no-cache-dir \
        sqlalchemy \
        flask \
        requests \
        python-magic \
        tika \
        langdetect

COPY scan_service.py .
COPY ../MyLogger.py .

CMD ["python", "scan_service.py"]

