# Orcest AI Login Portal

Single Sign-On (SSO) for the Orcest AI ecosystem, powered by [Authentik](https://goauthentik.io/).

## Deployment

Deployed at **login.orcest.ai** via Render Blueprint (`render.yaml`).

## Architecture

- **Authentik Server** - Identity Provider with OIDC/SAML/LDAP
- **PostgreSQL** - User/session storage (Render managed database)

## OIDC Clients

| Service | Client ID | Redirect URI |
|---------|-----------|-------------|
| RainyModel Admin | `rainymodel` | `https://rm.orcest.ai/auth/callback` |
| Lamino | `lamino` | `https://llm.orcest.ai/auth/callback` |
| Maestrist | `maestrist` | `https://agent.orcest.ai/auth/callback` |

## Initial Setup

After first deployment:

1. Visit `https://login.orcest.ai/if/flow/initial-setup/`
2. Create the initial admin account
3. Create OIDC applications for each service
4. Configure branding (Orcest AI logo, colors)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTHENTIK_SECRET_KEY` | Yes | Secret key for signing (generate with `openssl rand -hex 32`) |
| `AUTHENTIK_POSTGRESQL__*` | Yes | Database connection (auto-configured via Render Blueprint) |

## License

MIT
