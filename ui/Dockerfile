# Usa un'immagine Python leggera
FROM python:3.10-slim

# Imposta la directory di lavoro
WORKDIR /app

# Copia e installa le dipendenze Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia il resto del codice
COPY . .

# Espone la porta 5000
EXPOSE 5000

# Comando da eseguire quando il container parte
CMD ["python", "app.py"] 