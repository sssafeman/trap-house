FROM python:3.12-slim

# Docker GID is passed at build time to match the host's docker group.
# Default 999 works for most Debian/Ubuntu hosts. Override with:
#   docker compose build --build-arg DOCKER_GID=952 log-shipper
ARG DOCKER_GID=999

# Install docker CLI (not the full daemon) for reading endlessh container logs
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker-cli \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g ${DOCKER_GID} docker \
    && groupadd -r shipper \
    && useradd -r -g shipper -G docker -u 1000 shipper \
    && mkdir -p /data/db \
    && chown shipper:shipper /data/db

WORKDIR /app

COPY --chown=shipper:shipper shipper.py .

USER shipper

CMD ["python", "-u", "shipper.py"]