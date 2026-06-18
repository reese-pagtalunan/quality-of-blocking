# Consumer: tails goflow2 JSON and writes QoB counters into Redis.
# The qob package is bind-mounted at /app (see topology binds), so this image
# only needs Python + the redis client. arm64-native (python:slim is multi-arch).
FROM python:3.11-slim

RUN pip install --no-cache-dir "redis>=5.0"

ENV PYTHONPATH=/app
WORKDIR /app

CMD ["python", "/app/lab/consumer/run.py"]
