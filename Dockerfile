FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ARG WITH_CLASSIFIER=0
RUN if [ "$WITH_CLASSIFIER" = "1" ]; then \
      pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
      pip install --no-cache-dir transformers; fi
COPY pyproject.toml ./
COPY agentshield ./agentshield
RUN pip install --no-cache-dir .
COPY policies ./policies
COPY config.yaml ./
COPY sandbox ./sandbox
COPY demo/evil_server.py demo/office_server.py ./demo/
EXPOSE 8000
CMD ["uvicorn", "agentshield.app:app", "--host", "0.0.0.0", "--port", "8000"]
