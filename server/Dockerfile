FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libmagic1 && \
    pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY ../mserver.py .
COPY ../MyLogger.py .
COPY ../static ./static
COPY ../templates ./templates

CMD ["python", "server.py"]
