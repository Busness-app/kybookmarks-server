# Stage 1: Build Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Build Backend Binary
FROM golang:1.27-alpine AS backend-builder
WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /kybookmarks-server ./cmd/server

# Stage 3: Production Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app

RUN addgroup -S kybookmark && adduser -S kybookmark -G kybookmark

COPY --from=backend-builder /kybookmarks-server /usr/local/bin/kybookmarks-server
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

RUN mkdir -p /app/data /app/config && chown -R kybookmark:kybookmark /app/data /app/config

USER kybookmark

ENV PORT=5869 \
    DATA_DIR=/app/data \
    CONFIG_DIR=/app/config \
    WEB_DIR=/app/frontend/dist

EXPOSE 5869

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5869/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/kybookmarks-server"]
