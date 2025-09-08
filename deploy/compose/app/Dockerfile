
FROM python:3.11-slim
WORKDIR /app
# Install system deps
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*
# Copy repo and install library with extras
COPY . /app
RUN pip install --no-cache-dir .[adapters-fastapi,metrics] uvicorn prometheus-client
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "deploy.compose.app.service:app", "--host", "0.0.0.0", "--port", "8000"]
