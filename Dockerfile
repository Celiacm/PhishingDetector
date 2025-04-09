FROM python:3.10-slim

WORKDIR /app

COPY . .

# Instalar herramientas de compilación necesarias
RUN apt-get update && apt-get install -y build-essential gcc libssl-dev libffi-dev && rm -rf /var/lib/apt/lists/*

# Instalar librerías de Python
RUN pip install --no-cache-dir flask
RUN pip install --no-cache-dir python-dotenv
RUN pip install --no-cache-dir requests
RUN pip install --no-cache-dir requests-oauthlib
RUN pip install --no-cache-dir yagmail
RUN pip install --no-cache-dir schedule
RUN pip install --no-cache-dir pandas
RUN pip install --no-cache-dir yara-python
RUN pip install --no-cache-dir google-auth
RUN pip install --no-cache-dir google-auth-oauthlib
RUN pip install --no-cache-dir google-api-python-client
RUN pip install --no-cache-dir fpdf2
RUN pip install --no-cache-dir reportlab
RUN pip install --no-cache-dir matplotlib
RUN pip install --no-cache-dir dnspython
RUN pip install --no-cache-dir dkimpy

EXPOSE 5000

CMD ["python", "app.py"]
