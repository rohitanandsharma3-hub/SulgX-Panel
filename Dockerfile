FROM python:3.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
ENV HOME=/home/sulgx \
    PATH=/home/sulgx/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        gosu ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m sulgx && chown -R sulgx /app
COPY --from=builder /root/.local /home/sulgx/.local
RUN chown -R sulgx:sulgx /home/sulgx/.local
COPY --chown=sulgx . .
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; port=os.environ.get('PORT','8000'); urllib.request.urlopen(f'http://localhost:{port}/health')"
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
