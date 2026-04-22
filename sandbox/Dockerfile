# ─── Build stage ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /build

RUN apk add --no-cache nodejs npm

COPY go.mod go.sum ./
RUN go mod download

COPY . .
WORKDIR /build/claw_wallet_frontend_gateway
RUN npm ci
RUN npm run build

WORKDIR /build/sandbox
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o sandbox .

# ─── Runtime stage ──────────────────────────────────────────────────────────
# Use distroless for minimal attack surface
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /build/sandbox /app/sandbox
COPY policy.json               /app/policy.json

# Share3 is mounted at runtime via Docker volume / secrets
# ENV SHARE3_PATH=/run/secrets/share3.json   # default in main.go
# ENV POLICY_PATH=/app/policy.json           # default in main.go
# ENV RELAY_URL=https://api.clay.xyz
# Single-sandbox runtime: backend routes to the current sandbox connection internally.
# LISTEN_ADDR / CLAY_SANDBOX_URL in .env.clay are informational; the process binds the first free
# TCP port from 9000 on 127.0.0.1 and writes the actual URL back to .env.clay.

EXPOSE 9000
ENTRYPOINT ["/app/sandbox"]
