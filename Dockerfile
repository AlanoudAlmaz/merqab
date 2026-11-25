# MIRQAB production image (Render / any container host). TLS is terminated by the host; the app sees X-Forwarded-*.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 MIRQAB_DATA_DIR=/app/data
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-ara tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ai ./ai
COPY backend ./backend
COPY frontend ./frontend
COPY sample_data ./sample_data
RUN useradd --create-home --uid 10001 mirqab && mkdir -p /app/data && chown -R mirqab /app/data
USER mirqab
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn --factory backend.app.main:create_app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' --timeout-keep-alive 30"]
