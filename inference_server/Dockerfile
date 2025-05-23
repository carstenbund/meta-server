# syntax=docker/dockerfile:1
FROM python:3.10-slim

# 1. Set working directory
WORKDIR /app

# 2. Install minimal required system packages
RUN apt-get update && \
    apt-get install -y gcc libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# 3. Install CPU-only PyTorch and TorchVision first
RUN pip install --no-cache-dir torch==1.13.1+cpu torchvision==0.14.1+cpu \
    -f https://download.pytorch.org/whl/cpu/torch_stable.html

# 4. Then install the rest of your Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Download spaCy models at build time
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download nl_core_news_sm

# 6. Copy app code
COPY inference_server.py .

# 7. Run app
CMD ["python", "inference_server.py"]
