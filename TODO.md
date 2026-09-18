# Hoviyat — Remaining Tasks (Phase 1)

Based on PRD.md, TECHNICAL_DESIGN.md, and current implementation status.

---

## ✅ Completed (Walking Skeleton - Stage 1)

- [x] Project structure: layered Go backend (domain, repository, service, api, middleware, config)
- [x] PostgreSQL + GORM: user, tenant, membership models with AutoMigrate
- [x] Password auth: bcrypt hashing, register/login endpoints
- [x] JWT tokens: access (15min) + refresh (7d) with HS256, tenant-scoped claims
- [x] Basic RBAC: in-memory role→permission map, `RequirePermission` middleware
- [x] Multi-tenancy foundation: tenant provisioning API (create/suspend/reactivate/delete), membership model, tenant-switcher endpoint
- [x] REST API v1: `/auth/register`, `/auth/login`, `/auth/switch-tenant`, `/users/me`, `/tenants/*`
- [x] Error responses: machine-readable code + message (i18n-ready)
- [x] Config via env vars with local defaults

---

## 🔄 Stage 2: Multi-Tenancy Enhancements (In Progress / Next)

### Tenant & Membership Features
- [ ] Team/Department model nested under tenant (PRD §9: "nested — a tenant can contain teams/departments")
- [ ] Role assignments at team level (additive with tenant-level roles, PRD §9)
- [ ] Membership: list user's tenants (for tenant-switcher UI), leave tenant
- [ ] Tenant status: pending → active (email verification, PRD §9), suspended
- [ ] Self-service tenant signup with rate limiting (5/IP/hr, 1/email/day, CAPTCHA, PRD §7/§9)
- [ ] Risk-signal-based review queue for suspicious signups (disposable email, VPN/proxy/Tor, velocity, PRD §9/§10)

### Data Isolation
- [ ] Verify cross-tenant isolation tests (PRD §12: "dedicated cross-tenant isolation tests")
- [ ] Row-level security policies or query-level tenant scoping enforcement

---

## ⏳ Stage 3: ACL + ABAC (Authorization Engine)

### ACL (Resource-Instance Permissions)
- [ ] ACL table: `(subject, resource_type, resource_id, permission, effect: allow/deny)`
- [ ] PostgreSQL as source of truth + Redis hot cache (PRD §9 "hybrid")
- [ ] Push-based cache invalidation on write (pub/sub or direct delete, PRD §9)
- [ ] ACL CRUD API (grant/revoke/check per resource instance)

### ABAC / OPA Integration
- [ ] Embed OPA (`github.com/open-policy-agent/opa/rego`) in-process (PRD §9)
- [ ] Policy store: versioned Rego policies per tenant (CRUD + dry-run/simulation endpoint, PRD §6)
- [ ] Unified authorization decision API: `POST /api/v1/authz/check` → evaluates RBAC → ACL → ABAC
- [ ] Decision cache in Redis with push invalidation (sub-100ms p99 target, PRD §7/§9)
- [ ] Role/Permission management API (persistence-backed, replace in-memory map)

### Admin Permissions as RBAC
- [ ] Define admin permissions: `user.manage`, `role.manage`, `policy.manage`, `audit.view`, `tenant.manage` (PRD §6)
- [ ] Granular admin roles delegable to non-platform operators

---

## ⏳ Stage 4: OAuth2/OIDC + SSO + MFA + Passwordless

### OAuth2/OIDC (Relying Party - Login with Google/GitHub/Generic OIDC)
- [ ] OAuth2/OIDC client registration per tenant (generic provider config)
- [ ] Authorization code flow with PKCE
- [ ] Token exchange, user info mapping, account linking
- [ ] State/nonce handling, callback endpoint

### SAML 2.0 (Enterprise SSO)
- [ ] SAML 2.0 SP implementation (e.g., `crewjam/saml`, PRD §9)
- [ ] Metadata exchange, ACS endpoint, attribute mapping
- [ ] Generic spec compliance (vendor-specific quirks as follow-up, PRD §9)

### MFA
- [ ] TOTP: enrollment (QR code), verification, backup codes (PRD §6)
- [ ] Email/SMS OTP as secondary factor (pluggable delivery interface, PRD §6)

### Passwordless
- [ ] Magic link login (email-delivered, short-lived token)
- [ ] WebAuthn / Passkeys (PRD §6: "passwordless login option... WebAuthn")
- [ ] Password policy: configurable per-tenant (min length, char classes), breached-password check (HaveIBeenPwned API)

### Account Security
- [ ] Account lockout / exponential backoff on failed attempts (PRD §7: 5 failed/15min)
- [ ] Password reset flow (token, expiry, rate-limited)
- [ ] Email verification for signup

---

## ⏳ Stage 5: IdP Mode (Hoviyat as Identity Provider)

### Client/App Registration (Developer Portal API)
- [ ] OAuth2/OIDC client registration API (self-service, PRD §9/§184)
- [ ] Client credentials (client_id/secret) issuance, rotation
- [ ] Redirect URI validation, allowed scopes configuration

### Consent & Token Issuance
- [ ] Consent screen backing API (requested scopes/claims, remember consent, PRD §130)
- [ ] OAuth2/OIDC token issuance to third-party clients (access + refresh + ID tokens)
- [ ] Standard scopes: `openid`, `profile`, `email` + custom: roles/permissions, tenant_id (PRD §186)

### JWKS & Key Rotation
- [ ] JWKS endpoint (`/.well-known/jwks.json`, PRD §6)
- [ ] Automatic JWT signing key rotation on schedule (PRD §6)
- [ ] Token validation against current + recent keys (SDK/client support)

---

## ⏳ Stage 6: Compliance & Operations

### Audit Logging
- [ ] Immutable audit log: logins, token issuance/revocation, role/permission/policy changes (who, what, when, before/after)
- [ ] Append-only storage, tamper-evident
- [ ] Audit log viewer API (filtering, export, PRD §114)
- [ ] Retention period: resolve open question (PRD §10/§195)

### GDPR
- [ ] User data export endpoint (machine-readable JSON, PRD §187)
- [ ] Right to erasure: account + PII deletion with audit trail of deletion
- [ ] PII minimization in logs

### SOC2 Access Reviews
- [ ] Periodic report generation: who has access to what, stale/unused grants
- [ ] Session/device listing per user

### Observability
- [ ] Structured logging (JSON)
- [ ] Prometheus metrics: request latency, error rates, authz decision latency, cache hit/miss
- [ ] Grafana dashboards
- [ ] OpenTelemetry distributed tracing

### Webhooks / Events
- [ ] Event system: `user.created`, `role.updated`, `login.succeeded`, `login.failed`, etc. (PRD §6)
- [ ] Signed payloads, retry with exponential backoff

### SCIM 2.0 + CSV Provisioning
- [ ] SCIM 2.0 endpoints for automated user provisioning (Okta, Azure AD)
- [ ] CSV bulk import as fallback

---

## ⏳ Stage 7: Multi-Region HA

- [ ] Async PostgreSQL replication (active-passive, cloud-agnostic)
- [ ] Redis cross-region replication / sentinel
- [ ] Automated failover (health checks, promotion)
- [ ] DR validation: RTO < 30min, RPO < 5min (PRD §7/§144)
- [ ] Chaos/failover testing (PRD §12)

---

## 📦 Additional Phase 1 Requirements

### Go SDK (`pkg/sdk/`)
- [ ] Go client SDK wrapping REST/gRPC
- [ ] Middleware for net/http, chi, gin, echo (PRD §6)
- [ ] Contract tests keeping SDK, OpenAPI, gRPC in sync (PRD §12)

### gRPC API
- [ ] Protobuf definitions for authz check, token validation
- [ ] gRPC server implementation

### API Documentation
- [ ] OpenAPI spec generation (swaggo annotations on handlers)
- [ ] Published spec at `/api/v1/openapi.json`

### Custom Domains & Branding (API Backing)
- [ ] Custom domain API: tenant adds domain, ACME/Let's Encrypt HTTP-01 challenge (PRD §9/§181)
- [ ] Per-tenant branding settings (logo, colors, tenant name for login/consent pages, PRD §6/§116)

### Machine-to-Machine Auth
- [ ] Static API keys per service (tenant-scoped, permission-scoped, PRD §6)
- [ ] Key rotation, revocation

### Testing & Quality (PRD §12 Acceptance Criteria)
- [ ] Load/performance testing: sub-100ms p99 authz, sub-200ms login
- [ ] Fuzz testing of REST/gRPC inputs (CI)
- [ ] Contract tests: SDK ↔ OpenAPI ↔ gRPC in sync
- [ ] Full RBAC × ACL × ABAC decision matrix tests
- [ ] Cross-tenant isolation tests (automated)
- [ ] Security audit / pentest (no unresolved high/critical)

### Infrastructure
- [ ] Dockerfile + docker-compose for local dev
- [ ] Kubernetes manifests / Helm chart (`deploy/`)
- [ ] GitHub Actions CI: build, test, lint, contract tests
- [ ] GitOps deployment (ArgoCD/Flux config)
- [ ] Secrets management: Kubernetes Secrets + sealed-secrets/SOPS (PRD §6)

### Documentation & OSS
- [ ] CONTRIBUTING.md, issue/PR templates, code of conduct (PRD §11)
- [ ] API reference docs
- [ ] Architecture decision records (ADRs)

---

## 🎯 Phase 2 (Admin Panel - React) - Out of Scope for This TODO

- React admin panel (Vite + TypeScript + TanStack Query + shadcn/ui)
- Dogfoods Hoviyat auth APIs
- User management, role/permission/ACL/ABAC editors, audit viewer, access reviews, branding settings, tenant provisioning UI

---

## 🎯 Phase 3 (End-User Panel - Next.js) - Out of Scope for This TODO

- Next.js end-user panel
- Login/signup, MFA enrollment, profile/session management
- Developer portal (client registration), consent screens
- GDPR self-service (export, delete)

---

## Notes

- **Priority order** follows TECHNICAL_DESIGN.md build sequence (walking skeleton → multi-tenancy → ACL/ABAC → OAuth/SSO/MFA → IdP → Compliance → HA)
- **Aggressive timeline** (< 1 month for Phase 1 MVP per PRD §14) — sequence as independently mergeable stages
- **Cloud-agnostic**: no managed-service coupling (RDS, Cloud SQL, etc.) — use portable K8s + Postgres + Redis primitives
- **Self-hosted OSS only** (Apache-2.0, PRD §11) — no SaaS/managed offering in Phases 1–3