FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MUX_HOST=0.0.0.0 \
    MUX_PORT=5050 \
    PLAINBOOK_INSTANCE_USER=pbinstance \
    PLAINBOOK_USE_BWRAP=false

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends procps bubblewrap git \
    && groupadd --system pbinstance \
    && useradd --system --create-home --gid pbinstance --shell /usr/sbin/nologin pbinstance \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt

# Refresh dependency layer when the plainbook user_studies branch head changes.
ADD https://api.github.com/repos/lucadealfaro/plainbook/commits/user_studies /tmp/plainbook-user_studies-head.json

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod 750 /app \
    && mkdir -p runtime \
    && mkdir -p template

USER root

EXPOSE 5050

CMD ["python", "app.py"]