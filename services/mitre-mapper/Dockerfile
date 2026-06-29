FROM python:3.12-slim

RUN pip install --no-cache-dir pyyaml==6.0.2 \
    && groupadd -r mapper && useradd -r -g mapper -u 1000 mapper \
    && mkdir -p /data/db /config

WORKDIR /app

COPY --chown=mapper:mapper mapper.py .

USER mapper

CMD ["python", "-u", "mapper.py"]