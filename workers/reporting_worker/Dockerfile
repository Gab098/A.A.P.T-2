# Usa un'immagine Python ufficiale come base
FROM python:3.8-slim

# Imposta la directory di lavoro nel container
WORKDIR /app

# Copia il file dei requisiti e installa le dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia il codice sorgente del worker e i template
COPY . .

# Comando per avviare il worker
CMD ["python", "main.py"]
