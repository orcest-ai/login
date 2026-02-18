FROM ghcr.io/goauthentik/server:2024.12

ENV AUTHENTIK_LISTEN__HTTP=0.0.0.0:${PORT:-9000}
