# syntax=docker/dockerfile:1

# --- Stage 1: bundle the TypeScript frontend -------------------------------
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- Stage 2: build the Go binary and the WASM crypto core -----------------
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The crypto core compiled for the browser.
RUN GOOS=js GOARCH=wasm go build -trimpath -o web/dist/underflow.wasm ./wasm \
    && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/dist/wasm_exec.js
# Frontend assets from stage 1.
COPY --from=web /src/web/dist/app.js       web/dist/app.js
COPY --from=web /src/web/dist/app.css      web/dist/app.css
COPY --from=web /src/web/dist/index.html   web/dist/index.html
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/underflow ./cmd/underflow

# --- Stage 3: minimal runtime ----------------------------------------------
FROM alpine:3.20 AS runtime
RUN adduser -D -u 10001 underflow \
    && mkdir -p /var/lib/underflow \
    && chown underflow:underflow /var/lib/underflow
COPY --from=build /out/underflow /usr/local/bin/underflow
USER underflow
WORKDIR /var/lib/underflow
ENV UF_LISTEN_ADDR=0.0.0.0:8080 \
    UF_DB_DRIVER=sqlite \
    UF_DB_DSN=/var/lib/underflow/underflow.db
EXPOSE 8080
VOLUME ["/var/lib/underflow"]
ENTRYPOINT ["/usr/local/bin/underflow"]
CMD ["serve"]
