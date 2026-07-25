FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_addon.py .

EXPOSE 8080 8081

CMD ["mitmdump", "-s", "sentinel_addon.py", "--listen-host", "0.0.0.0", "--listen-port", "8080"]
