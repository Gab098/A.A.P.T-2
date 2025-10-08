# Usa un'immagine Python con Go
FROM python:3.10-slim

# Imposta la directory di lavoro
WORKDIR /app

# Installa Go, nuclei e tool utili per pentesting/ricognizione
RUN apt-get update && apt-get install -y wget git \
    nmap iputils-ping curl dnsutils whois netcat-openbsd \
    masscan gobuster ffuf iproute2 \
    && wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz \
    && rm go1.21.0.linux-amd64.tar.gz \
    && export PATH=$PATH:/usr/local/go/bin \
    && GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
    && GO111MODULE=on go install -v github.com/owasp-amass/amass/v4/...@latest \
    && GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && ln -s /root/go/bin/nuclei /usr/local/bin/nuclei \
    && ln -s /root/go/bin/amass /usr/local/bin/amass \
    && ln -s /root/go/bin/subfinder /usr/local/bin/subfinder \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copia e installa le dipendenze Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia il resto del codice
COPY . .

# Comando da eseguire quando il container parte
CMD ["python", "main.py"] 