FROM kalilinux/kali-rolling

RUN apt-get update && \
    apt-get install -y metasploit-framework python3 python3-pip git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "main.py"] 