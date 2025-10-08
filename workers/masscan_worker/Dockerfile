FROM python:3.10-slim

WORKDIR /app

# Installa masscan
RUN apt-get update && apt-get install -y masscan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -ms /bin/bash masscanuser
USER masscanuser

CMD ["python", "main.py"]