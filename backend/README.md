# Hoviyat backend

Go auth/authz service for Hoviyat. See [../docs/PRD.md](../docs/PRD.md) and
[../docs/TECHNICAL_DESIGN.md](../docs/TECHNICAL_DESIGN.md) for product
scope and architecture.

## Current stage: walking skeleton

Implements the first build stage from the technical design doc:
password registration/login, JWT access+refresh token issuance, and a
basic coarse-grained RBAC permission check, backed by PostgreSQL, single
region, no cache yet.

Not yet implemented (tracked as later build stages): multi-tenancy, ACL/ABAC
via OPA, OAuth2/OIDC/SAML SSO, MFA, passwordless, IdP mode, audit/GDPR/SOC2
tooling, gRPC API, and multi-region HA.

## Running locally

Requires a PostgreSQL instance reachable via `HOVIYAT_DATABASE_URL` (defaults
to `postgres://hoviyat:hoviyat@localhost:5432/hoviyat?sslmode=disable`).

```sh
go run ./cmd/hoviyat
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `HOVIYAT_HTTP_ADDR` | `:8080` | HTTP listen address |
| `HOVIYAT_DATABASE_URL` | see above | Postgres DSN |
| `HOVIYAT_JWT_SECRET` | `dev-secret-change-me` | HMAC secret for signing JWTs — set a real secret outside local dev |

## API (v1)

- `POST /api/v1/auth/register` — `{email, password}` → token pair
- `POST /api/v1/auth/login` — `{email, password}` → token pair
- `GET /api/v1/users/me` — bearer-authenticated, requires `self:read` permission
- `GET /healthz` — liveness check

## Testing

```sh
go test ./...
```

Service and HTTP-handler tests run against in-memory fakes and don't require
a database. `golang-migrate`/testcontainers-backed integration tests are
planned for the multi-tenancy build stage.
