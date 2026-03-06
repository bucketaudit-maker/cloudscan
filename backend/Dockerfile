FROM python:3.12-slim

WORKDIR /srv

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application
COPY . /srv/backend
ENV PYTHONPATH=/srv

# Create data directory
RUN mkdir -p /srv/backend/data

EXPOSE 8000

# Production: gunicorn with threading for SSE support
CMD ["gunicorn", "backend.app.main:app", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--threads", "4", \
     "--timeout", "120", \
     "--keep-alive", "65", \
     "--access-logfile", "-"]
