FROM node:20-alpine AS web-builder
WORKDIR /build/web
ARG NPM_CONFIG_REGISTRY

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
ARG PIP_INDEX_URL

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY --from=web-builder /build/web/dist /app/web/dist

RUN mkdir -p /app/models/astrlink-guard/int8 /app/data/tmp_uploads /app/data/artifacts

WORKDIR /app/backend

EXPOSE 18100

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import os, sys, urllib.request; port = os.environ.get('DS_PORT', '18100'); r = urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3); sys.exit(0 if r.status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "18100", "--workers", "1"]
