FROM python:3.12-slim

# Install build tools needed for argon2-cffi C extension
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose FastAPI port
EXPOSE 8000

CMD ["uvicorn", "zerovault.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
