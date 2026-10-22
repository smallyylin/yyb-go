# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.23-bookworm AS build

WORKDIR /src

# Copy manifests first so the module download layer is cached across code edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is not needed: the SQLite driver is modernc.org/sqlite (pure Go), so we
# can build a fully static binary that runs on a scratch/distroless base.
# -trimpath removes local filesystem paths; -s -w strips debug symbols.
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w" -o /out/yyb-go ./cmd/yyb-go

# ---- runtime stage ----
FROM debian:bookworm-slim

# ca-certificates is required for the outbound HTTPS calls (WeChat OAuth and
# the yybadaccess API). tzdata keeps log timestamps interpretable.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 yyb \
 && useradd -r -u 10001 -g yyb -s /usr/sbin/nologin yyb

WORKDIR /app

COPY --from=build /out/yyb-go /app/yyb-go
COPY resource /app/resource

# Writable state (SQLite db, avatars, generated QR images) lives here. The
# process drops to an unprivileged user, so this tree must be owned by it.
RUN mkdir -p /app/resource/db /app/resource/avatars /app/resource/qr /app/resource/static/css /app/resource/static/js \
 && chown -R yyb:yyb /app/resource

USER yyb

ENV TZ=Asia/Shanghai \
    YYB_AUTH_USER=admin

EXPOSE 8000

# The server validates its own configuration at startup and exits non-zero when
# the auth token is missing, so an unauthenticated container cannot come up.
ENTRYPOINT ["/app/yyb-go"]
CMD ["-host", "0.0.0.0", "-port", "8000", "-resource-root", "/app/resource"]
