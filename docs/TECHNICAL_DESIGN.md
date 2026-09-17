# Hoviyat — Technical Design (Phase 1)

Companion to [PRD.md](./PRD.md). Covers repo layout, backend project structure, stack choices, and build sequencing for Phase 1. Implementation-level detail; product requirements and rationale live in the PRD.

## Repo layout

Monorepo:

```
hoviyat/
├── backend/           # Go auth/authz service (Phase 1)
├── admin-panel/        # React admin panel (Phase 2)
├── web/                 # React end-user panel (Phase 3)
├── docs/
│   ├── PRD.md
│   └── TECHNICAL_DESIGN.md
└── .github/workflows/    # CI (GitHub Actions)
```

Rationale: simpler versioning/releases across phases, easier for OSS contributors to find everything in one place, matches the PRD's phased delivery without forcing cross-repo coordination early.

## Backend project structure (layered)

```
backend/
├── cmd/
│   └── hoviyat/                 # main entrypoint
├── internal/
│   ├── api/                     # HTTP/gRPC handlers, request/response DTOs, routing (gin)
│   ├── service/                 # business logic: auth, rbac, abac, tenant, audit, etc.
│   ├── repository/              # data access: GORM models + sqlc queries, interfaces consumed by service/
│   ├── domain/                  # core entities and interfaces (User, Tenant, Role, Policy, ...), no framework deps
│   ├── middleware/               # auth middleware, rate limiting, tenant scoping
│   └── config/                   # config loading (env/flags)
├── pkg/
│   └── sdk/                      # public Go client SDK (importable by external services)
├── migrations/                    # golang-migrate SQL migration files
├── db/
│   └── queries/                   # sqlc .sql query files + generated code
├── policies/                       # OPA/Rego policy definitions (embedded via rego library)
└── deploy/                          # Kubernetes manifests / Helm chart, ArgoCD/Flux config
```

Layering rule: `domain` has no dependencies on anything else. `repository` implements `domain` interfaces using GORM/sqlc. `service` depends on `domain` interfaces (not concrete repository types), enabling test doubles. `api` depends on `service`, translates HTTP/gRPC ⇄ domain types.

## Stack decisions

| Concern | Choice | Notes |
|---|---|---|
| HTTP router | Gin | Chosen over chi for its middleware ecosystem and familiarity |
| DB access | GORM (primary) + sqlc (hot-path/complex queries) | GORM for standard CRUD (users, tenants, roles, teams — faster to build); sqlc for the authorization decision hot path and complex ACL queries where sub-100ms latency (PRD §7) and precise query control matter more than ORM convenience |
| Migrations | golang-migrate | Framework-agnostic, works with both GORM and sqlc-managed tables |
| Policy engine | OPA embedded (`open-policy-agent/opa/rego`) | Per PRD §9 — in-process, no sidecar |
| Cache/sessions | Redis (go-redis) | Per PRD §7/§9 — decision cache, refresh token denylist, rate limiting |
| gRPC | google.golang.org/grpc + protobuf | Service-to-service authorization checks (PRD §6) |
| Testing | testify + dedicated RBAC/ACL/ABAC matrix suite, testcontainers-go for Postgres/Redis integration tests | Matches PRD §12 acceptance criteria |

## Build sequence (walking skeleton first)

Per the PRD's timeline/risk notes (§13/§14), Phase 1 is sequenced rather than built as one atomic deliverable:

1. **Walking skeleton:** password login → JWT issuance → basic RBAC role check → PostgreSQL, single region, no cache yet. Proves the layered structure end-to-end.
2. **Multi-tenancy:** tenant/team model, row-level scoping, tenant-switcher on tokens.
3. **ACL + ABAC:** resource-instance ACL table, embedded OPA, unified decision API, Redis decision cache with push-based invalidation.
4. **OAuth2/OIDC + SSO (SAML) + MFA + passwordless.**
5. **IdP mode:** client registration, consent screens' backing API, JWKS endpoint, scopes/claims.
6. **Compliance & ops:** audit log, GDPR export/erasure, SOC2 access review reports, webhooks, SCIM/CSV provisioning.
7. **Multi-region HA:** async replication, automated failover, DR validation against the RTO<30min/RPO<5min target.

Each stage should be independently testable and mergeable — later stages build on, but don't block release of, earlier ones (consistent with the PRD's risk mitigation for the aggressive timeline).
