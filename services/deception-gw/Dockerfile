FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -r app && useradd -r -g app -u 1000 app \
    && mkdir -p /var/log/trap-house \
    && chown app:app /var/log/trap-house

COPY --chown=app:app . .

USER app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]