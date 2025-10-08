FROM python:3.10-slim

WORKDIR /app

# Install httpx
RUN apt-get update && apt-get install -y wget git ca-certificates \
    && wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz \
    && rm go1.21.0.linux-amd64.tar.gz \
    && export PATH=$PATH:/usr/local/go/bin \
    && GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && ln -s /root/go/bin/httpx /usr/local/bin/httpx \
    && apt-get remove -y wget \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -ms /bin/bash httpxuser
USER httpxuser

CMD ["python", "main.py"]