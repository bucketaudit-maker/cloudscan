FROM python:3.12-slim

WORKDIR /srv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY backend /srv/backend

RUN useradd --create-home --uid 10001 bucketaudit && \
    mkdir -p /srv/backend/data && \
    chown -R bucketaudit:bucketaudit /srv/backend

USER bucketaudit
WORKDIR /srv/backend

EXPOSE 8000

# Railway injects PORT at runtime; 8000 remains the local default.
CMD ["sh", "-c", "exec gunicorn backend.app.main:app --bind 0.0.0.0:${PORT:-8000} --workers ${GUNICORN_WORKERS:-1} --threads ${GUNICORN_THREADS:-8} --timeout ${GUNICORN_TIMEOUT:-120} --graceful-timeout 30 --keep-alive 65 --access-logfile - --error-logfile -"]
