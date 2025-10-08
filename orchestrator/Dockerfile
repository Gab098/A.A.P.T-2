FROM python:3.10-slim

WORKDIR /app

# Installa tool di build necessari per llama-cpp-python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "orchestrator_v2.py"] 