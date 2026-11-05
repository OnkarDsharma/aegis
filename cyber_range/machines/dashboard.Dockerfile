FROM docker.io/library/python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY aegis ./aegis
COPY frontend ./frontend

EXPOSE 8000
CMD ["python", "-m", "aegis", "serve"]
