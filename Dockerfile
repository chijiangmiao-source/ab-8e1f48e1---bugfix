# Pure-stdlib Python service: no third-party packages, no network build needed.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    AUDIT_DB=/data/audit.db

WORKDIR /srv

COPY app/ ./app/
COPY tests/ ./tests/

RUN mkdir -p /data && python -m py_compile app/*.py tests/*.py

# Container-local health probe (uses the stdlib, the image has no curl).
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status==200 else 1)"

EXPOSE 8080

CMD ["python", "app/server.py"]
