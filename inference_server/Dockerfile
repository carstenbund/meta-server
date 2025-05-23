# llm_inference_server/Dockerfile

FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y gcc libmagic1 && \
    pip install --no-cache-dir -r requirements.txt

COPY inference_server.py .

CMD ["python", "inference_server.py"]

