# Stage 1: build the Svelte login/consent UI
FROM node:22-alpine AS ui
WORKDIR /build
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY ui/ ./
RUN VITE_OUT_DIR=/build-out npm run build

# Stage 2: runtime
FROM python:3.12-slim AS runtime
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/
COPY --from=ui /build-out/ src/mcp_gateway/static/ui/

RUN pip install --no-cache-dir .

# Non-root user; data volume for the SQLite store
RUN useradd -r -u 10001 gateway && mkdir -p /data && chown gateway /data
USER gateway
VOLUME /data

ENV MCP_GATEWAY_CONFIG=/config/config.yaml
EXPOSE 8000

CMD ["mcp-gateway", "run"]
