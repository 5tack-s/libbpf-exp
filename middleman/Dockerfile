FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Expose the FastAPI port
EXPOSE 8000

# The UNIX socket path is mounted from the host via a volume
CMD ["python", "main.py"]
