FROM python:3.12-slim

WORKDIR /srv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application
COPY . /srv/backend

# Run as an unprivileged user in production.
RUN useradd --create-home --uid 10001 cloudscan && \
    mkdir -p /srv/backend/data && \
    chown -R cloudscan:cloudscan /srv/backend
USER cloudscan
WORKDIR /srv/backend

EXPOSE 8000

# Keep one worker until scan events and active-job state move to Redis.
# The shell expands Railway's injected PORT while retaining 8000 locally.
CMD ["sh", "-c", "exec gunicorn backend.app.main:app --bind 0.0.0.0:${PORT:-8000} --workers ${GUNICORN_WORKERS:-1} --threads ${GUNICORN_THREADS:-8} --timeout ${GUNICORN_TIMEOUT:-120} --graceful-timeout 30 --keep-alive 65 --access-logfile - --error-logfile -"]
