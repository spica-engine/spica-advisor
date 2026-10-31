FROM python:3.14-slim

ARG CLAUDE_CODE_VERSION=2.1.316

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force \
    && apt-get purge -y npm \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY spica_advisor ./spica_advisor

# GitHub Actions mounts the repository here and requires container actions to run as root.
WORKDIR /github/workspace

ENTRYPOINT ["python", "/app/main.py"]
