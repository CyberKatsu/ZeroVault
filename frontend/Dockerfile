FROM python:3.12-slim

# Node.js is required by Reflex's frontend compilation step
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libffi-dev \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Reflex init creates .web directory on first run
RUN reflex init

EXPOSE 3000 8001

CMD ["reflex", "run", "--env", "dev"]
