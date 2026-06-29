FROM python:3.12-slim

# Install docker CLI (not the full daemon) for reading endlessh container logs
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker-cli \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 952 docker \
    && groupadd -r shipper \
    && useradd -r -g shipper -G docker -u 1000 shipper \
    && mkdir -p /data/db \
    && chown shipper:shipper /data/db

WORKDIR /app

COPY --chown=shipper:shipper shipper.py .

USER shipper

CMD ["python", "-u", "shipper.py"]