FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install flask mitmproxy requests gunicorn

WORKDIR /app

COPY . .

# Permissões totais na pasta temporária para o mitmproxy gerar certificados
RUN mkdir -p /tmp/.mitmproxy && chmod -R 777 /tmp/.mitmproxy
RUN touch licencas.json && chmod 777 licencas.json

# O Railway vai injetar a variável PORT
EXPOSE 8080

CMD ["python", "main_railway.py"]
