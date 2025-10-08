FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y python3 python3-pip wget unzip git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Scarica linpeas e winPEAS
RUN wget -O /app/linpeas.sh https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && \
    chmod +x /app/linpeas.sh && \
    wget -O /app/winPEAS.bat https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "main.py"] 