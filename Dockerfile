# CyberTrace-Lite - container image
# Runs the same waitress-served Flask app as `python app.py` locally.
FROM python:3.13-slim

WORKDIR /app

# Install dependencies first so this layer is cached across code-only changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Data that must survive container restarts (SQLite DB, session secret key).
VOLUME ["/app/database"]

# 127.0.0.1 (app.py's local-run default) isn't reachable from outside the
# container's network namespace - bind on all interfaces here instead.
ENV CT_HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "app.py"]
