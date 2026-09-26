FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY agentshield ./agentshield
RUN pip install --no-cache-dir .
COPY policies ./policies
COPY config.yaml ./
COPY sandbox ./sandbox
EXPOSE 8000
CMD ["uvicorn", "agentshield.app:app", "--host", "0.0.0.0", "--port", "8000"]
