# Hoviyat — Product Requirements Document

**Product name:** Hoviyat ("identity" in Persian)
**Repo:** https://github.com/arashrasoulzadeh/hoviyat
**Status:** Draft v1
**Owner:** Arash Rasoulzadeh
**Last updated:** 2026-09-17

## 1. Summary

Hoviyat is a multi-tenant authentication and authorization platform written in Go, providing identity management, RBAC/ACL/ABAC-based access control, and a policy engine (OPA) for fine-grained, attribute-based decisions. It exposes REST and gRPC APIs plus a Go middleware/SDK for service integration, backed by PostgreSQL and Redis, and is designed for high availability across multiple regions.

Hoviyat is self-hosted open source only — there is no managed/hosted SaaS offering ("Hoviyat Cloud") in scope for Phases 1–3; operators deploy and run their own instance.

Delivery is phased:
- **Phase 1** — Core auth/authz backend (this PRD's primary scope)
- **Phase 2** — React admin panel (tenant/org administration, role & policy management)
- **Phase 3** — React front-end panel (end-user facing: login, profile, MFA setup, consent)

## 2. Internationalization

Hoviyat ships with English and Farsi (fa) support from Phase 1, reflecting the product's Persian branding — API error messages/codes support localized text (machine-readable error codes plus a localized message field), and Phase 2/3 UIs are built with i18n (RTL-aware layout for Farsi) from the start rather than retrofitted later.

## 3. Goals

- Provide a single source of truth for identity, roles, and permissions across multiple isolated tenants (organizations).
- Support both coarse-grained RBAC and fine-grained ABAC policies via a unified policy engine.
- Be embeddable: any internal or external service can authenticate users and authorize actions via REST, gRPC, or a Go SDK.
- Meet enterprise-grade non-functional requirements: 99.9%+ uptime, sub-100ms authorization checks, multi-region HA.
- Support baseline compliance needs: full audit logging, GDPR data handling, and SOC2-style access reviews.

## 4. Non-goals (Phase 1)

- No admin UI (Phase 2) or end-user UI (Phase 3) — Phase 1 is API/SDK only.
- No billing/subscription management.
- No non-Go client SDKs (only REST/gRPC contracts, consumable from any language; a dedicated Go SDK ships in Phase 1, other language SDKs are future work).

## 5. Users & personas

| Persona | Description | Needs from Hoviyat |
|---|---|---|
| End user | Person authenticating into a tenant's application | Login (password/OAuth2/OIDC/SSO), MFA, session management |
| Tenant admin | Admin of one organization/tenant | Manage users, roles, ACL/ABAC policies within their tenant (Phase 2 UI) |
| Platform operator | Operates Hoviyat itself across tenants | Tenant provisioning, global audit visibility, SLA monitoring |
| Integrating service (machine) | Backend service calling Hoviyat to authn/authz requests | REST/gRPC API, Go middleware/SDK, low-latency policy checks |

## 6. Scope by phase

### Phase 1 — Backend auth/authz platform (Go)

**Identity & authentication**
- Username/password registration & login, with secure password hashing (Argon2id/bcrypt).
- JWT-based access + refresh token issuance, rotation, and revocation.
- OAuth2/OIDC login (Google, GitHub, and generic OIDC provider config).
- SSO via SAML 2.0 and OIDC for enterprise tenants.
- SCIM 2.0 support for automated user provisioning/deprovisioning from enterprise IdPs (Okta, Azure AD), plus CSV bulk import as a simpler manual fallback for tenants without SCIM-capable directories.
- MFA: TOTP (authenticator apps), plus email/SMS OTP as secondary factors.
- Password reset, account lockout/rate limiting on failed attempts.
- Password policy: configurable per-tenant complexity rules (min length, character classes), breached-password check against a service like HaveIBeenPwned at signup/reset, and a passwordless login option (magic link and/or WebAuthn) as an alternative to password+MFA.
- Identity provider (IdP) role: Hoviyat can also issue OAuth2/OIDC tokens to registered third-party client applications ("Login with Hoviyat"), in addition to consuming external providers as a relying party. Phase 1 covers client/app registration and token issuance APIs; consent-screen UI ships in Phase 3.

**Multi-tenancy**
- Tenant (organization) as a first-class entity; all roles, policies, and audit logs scoped to a tenant.
- Tenant-level isolation of data at the storage layer (row-level scoping, tenant_id on all tables).
- Tenant provisioning API (create/suspend/delete tenant).
- A single user account (identity) can belong to multiple tenants, each with its own role/team memberships — analogous to Slack/GitHub org membership. Requires a tenant-switcher UX in Phase 2/3 and per-tenant scoping on every authorization check (a user's permissions in tenant A never leak into tenant B).
- Support impersonation: platform operators (and, where a tenant permits it, tenant admins) can start an impersonated session as another user for support/debugging. Every impersonated session is fully audit-logged (who impersonated whom, when, and what actions were taken while impersonating), and the impersonated user's own session is visibly marked/notifiable.
- Session/device policy: no hard cap on concurrent sessions per user; the refresh token lifetime (tenant-configurable, default e.g. 30 days) is the effective "remember me" duration, with the ability to revoke individual sessions/devices from Phase 3's session management UI.

**Authorization (RBAC + ACL + ABAC)**
- RBAC: users assigned roles; roles map to permissions; supports role hierarchies.
- ACL: resource-level grant/deny entries for exceptions beyond role defaults.
- ABAC: policy engine (OPA/Rego) evaluating attribute-based rules (user attributes, resource attributes, environment/context) for complex conditional access.
- Unified authorization decision API: a single "can user X do action Y on resource Z" check that evaluates RBAC → ACL → ABAC policy layers.
- Admin-panel permissions are not a separate system: administrative capabilities (user.manage, role.manage, policy.manage, audit.view, billing.manage-equivalent, etc.) are themselves ordinary RBAC permissions, evaluated through the same unified decision API. This lets a tenant admin delegate granular admin roles (e.g. "user admin" vs. "policy admin") to other users rather than only offering all-or-nothing tenant-admin access.
- Policy versioning and dry-run/simulation endpoint (test a policy change before activating it).

**Integration surface**
- REST API (OpenAPI spec) for all identity/authz operations, versioned via URL path (`/v1/...`) with semver; breaking changes bump the major path version with a documented deprecation window for prior versions.
- gRPC service for low-latency, service-to-service authorization checks.
- Go middleware package for HTTP frameworks (net/http, chi, gin, echo) to protect routes.
- Go client SDK wrapping REST/gRPC calls.
- Custom domains: tenants can point their own domain (e.g. `login.theirapp.com`) at Hoviyat's hosted login/consent pages, with per-tenant TLS certificate provisioning (e.g. via ACME/Let's Encrypt) rather than a shared domain only.
- Per-tenant branding: tenants can customize the hosted login/consent pages their end users see (logo, colors, tenant name) alongside custom domains. The admin panel itself (Phase 2) stays Hoviyat-branded, not white-labeled — branding customization applies to the Phase 3 end-user-facing surface only.
- Machine-to-machine (service) auth: static, per-service API keys (issued/rotated via the admin API, scoped to a tenant and a set of permissions), sent as a request header — no OAuth2 client_credentials flow or mTLS in Phase 1.
- JWT signing keys are rotated automatically on a schedule; Hoviyat exposes a JWKS endpoint so integrating services/SDKs can validate tokens against current and recently-rotated keys without manual key distribution.

**Data & infra**
- PostgreSQL as system of record (users, tenants, roles, permissions, ACL entries, policy metadata, audit log).
- Redis for session/token caching, rate limiting, and policy decision caching to hit latency targets.
- Deployment target: containerized (Docker/Kubernetes), stateless app tier, multi-region with active-active or active-passive replication for HA.
- CI/CD: GitHub Actions for build/test/CI, GitOps-style deployment (ArgoCD/Flux) to Kubernetes — fits the OSS, GitHub-hosted project model.
- Environments: dev and production (two-tier); local development runs against docker-compose rather than a shared dev environment.
- Go SDK versioning: strict semver, no breaking changes within a major version, kept in lockstep with the API's `/v1` path versioning (§6 Integration surface) and enforced via contract tests (§12).
- Secrets management: Kubernetes Secrets, encrypted at rest via sealed-secrets or SOPS, for Hoviyat's own operational secrets (DB credentials, JWT signing keys, OAuth client secrets) — no external secrets-manager dependency (e.g. Vault) required in Phase 1, consistent with the cloud-agnostic goal.
- Transactional email/SMS delivery (password reset, OTP, email verification) is provider-agnostic: Hoviyat defines a pluggable delivery interface, and operators configure their own provider (SendGrid, SES, Twilio, etc.) rather than Hoviyat bundling a specific default.

**Compliance & observability**
- Full audit log: immutable record of logins, token issuance/revocation, and all role/permission/policy changes (who, what, when, before/after state).
- GDPR: user data export endpoint, right-to-erasure (account + PII deletion with audit trail of the deletion itself), PII minimization in logs.
- Audit log retention period is not yet specified (open question, §10) — likely candidates are a 1-year tenant-configurable SOC2 baseline vs. a stricter regulatory-grade window; must be resolved before Phase 1's compliance features are considered complete, since it affects both storage sizing and GDPR data-minimization posture.
- SOC2-style access reviews: periodic report generation (who has access to what, stale/unused grants), session and device listing per user.
- Structured logging, metrics, and distributed tracing via Prometheus + Grafana + OpenTelemetry (open-source stack, consistent with the project's OSS model).
- Event/webhook system: integrating services can subscribe to real-time events (`user.created`, `role.updated`, `login.succeeded`, `login.failed`, etc.) via registered webhook endpoints, with signed payloads and retry/backoff on delivery failure.

### Phase 2 — Admin panel (React)

- Authenticates against Hoviyat's own auth APIs (dogfooding) — admins and platform operators log in the same way any integrating app's users would, exercising the product end-to-end.
- Web UI for tenant admins and platform operators.
- User management (invite, suspend, delete, reset MFA), including bulk CSV import and SCIM directory sync configuration/status (Phase 1 SCIM/CSV APIs, §6 Identity & authentication).
- Role & permission management (create roles, assign permissions, role hierarchy editor), including delegating granular admin roles (user admin, policy admin, audit viewer, etc.) rather than only full tenant-admin access.
- ACL editor for resource-level exceptions.
- ABAC/OPA policy editor with dry-run/simulation UI, using Phase 1's simulation endpoint.
- Audit log viewer with filtering/export.
- Access review dashboard (SOC2 reports).
- Branding settings for the tenant's hosted login/consent pages (logo, colors, custom domain) — the admin panel UI itself is not white-labeled.
- In-app and email alerts for security-relevant events (new admin added, suspicious login pattern, self-service tenant pending review, policy change by another admin).
- Tenant provisioning UI (platform-operator scope only).

### Phase 3 — End-user front-end panel (React)

- Authenticates against Hoviyat's own auth APIs (dogfooding), same as Phase 2.
- Self-service login/signup UI (password, OAuth2/OIDC, SSO redirect flows).
- MFA enrollment and management (TOTP setup, backup codes, OTP delivery preference).
- Profile & session management: list active sessions with device type, approximate location, and last-active timestamp; revoke an individual session; "log out everywhere" (revoke all but the current session); email alert on login from a new/unrecognized device or location; change password.
- Developer portal: self-service registration of third-party OAuth2/OIDC client apps ("Login with Hoviyat"), issuing client_id/secret immediately without operator approval (§9 IdP client registration).
- Consent screens for OAuth2/OIDC flows where Hoviyat acts as an identity provider to third-party apps.
- GDPR self-service: data export and account deletion requests.

## 7. Non-functional requirements

- **Availability:** 99.9%+ uptime SLA; multi-region deployment with automated failover.
- **Performance:** sub-100ms p99 latency for authorization (policy) checks; sub-200ms for login/token issuance.
- **Security:** encryption at rest and in transit, secrets management (no plaintext credentials), OWASP ASVS-aligned hardening, regular dependency/vuln scanning.
- **Rate limiting (concrete defaults, tenant-configurable):** 5 failed login attempts per account per 15 minutes triggers a temporary lockout (exponential backoff on repeat offenses); 100 requests/minute per API key by default for REST/gRPC calls; tenant creation limited to 5 per IP per hour and 1 per email per day.
- **Threat model:** Phase 1's security design explicitly defends against:
  - *Credential stuffing / brute force* — rate limiting, account lockout, breached-password checks.
  - *Token theft / replay* — short-lived access tokens, rotating refresh tokens with reuse detection, JWKS-based key rotation.
  - *Privilege escalation via policy misconfiguration* — RBAC/ACL/OPA policy changes go through the dry-run/simulation endpoint before activation, and every change is captured in the immutable audit log.
  - *Cross-tenant data leakage* — strict row-level tenant isolation at the storage layer, treated as a first-class, explicitly-tested security requirement (not just a data-modeling convenience), with dedicated cross-tenant isolation tests in the Phase 1 test suite (see §12).
- **Scalability:** stateless service tier horizontally scalable; Redis/Postgres sized for large-scale multi-tenant load; policy decisions cached to avoid per-request OPA evaluation cost where safe.
- **Auditability:** every write to identity/authz state produces an audit log entry; audit log is append-only.
- **Disaster recovery:** RTO < 30 minutes, RPO < 5 minutes — relaxed from an initial RTO<5min/RPO<1min target (see §13 Risks) specifically to preserve the cloud-agnostic goal: this target is achievable with portable active-passive async replication for PostgreSQL and Redis across regions, without requiring cloud-managed, non-portable replication features.
- **Observability:** Prometheus for metrics, Grafana for dashboards, OpenTelemetry for distributed tracing — instrumented from Phase 1 so latency/uptime SLOs (§12) are measurable, not just aspirational.

## 8. Architecture overview (Phase 1)

```
                     ┌───────────────────────┐
   Client apps ─────▶│   REST API / gRPC     │
   (via Go SDK or     │   (Hoviyat backend)   │
    direct calls)     └───────────┬───────────┘
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
           Identity/Auth     Authz Engine       Audit/Compliance
           (JWT, OAuth2/      (RBAC + ACL +      (audit log,
            OIDC, SAML,        OPA/ABAC,          GDPR export,
            MFA)               decision cache)    access reviews)
                  │                │                │
                  ▼                ▼                ▼
              PostgreSQL ◀───────────────────▶  Redis (cache/session)
              (multi-tenant, row-scoped)
```

## 9. Confirmed decisions

- **OPA deployment:** embedded in-process (Go library, via `github.com/open-policy-agent/opa/rego`), not a sidecar/centralized service — avoids a network hop to hit the sub-100ms p99 target.
- **Data residency:** not pinned per-region in Phase 1. Single primary region with additional regions used for failover/read replicas only; revisit per-tenant pinning if a tenant requires strict data sovereignty later.
- **Token strategy:** short-lived JWT access tokens (~15 min) + rotating refresh tokens. Each refresh rotates the token and invalidates the previous one; reuse of an already-rotated refresh token is treated as a compromise signal (revoke the whole token family). Revocation/denylist backed by Redis.
- **SSO/IdP validation:** support the SAML 2.0 and OIDC protocols generically in Phase 1; no specific named vendor (Okta, Azure AD, Google Workspace) is validated against yet — vendor-specific testing/quirks are follow-up work once a real tenant requests one.
- **Org structure:** nested — a tenant can contain teams/departments, and roles/ACL/ABAC scoping can apply at the team level as well as the tenant level.
- **Tenant onboarding:** self-service signup. Anyone can create a new tenant and becomes its first admin; platform operators retain override/suspend/delete capability.
- **Cloud target:** cloud-agnostic. Design against Kubernetes + PostgreSQL + Redis as portable primitives, no managed-service-specific coupling (e.g. no hard dependency on RDS/Cloud SQL) in Phase 1. A specific cloud target can be chosen at implementation time without changing the architecture.
- **Permission granularity:** resource-instance level (e.g. `document:123:read`, not just `document:read`), to support per-object sharing/ACL patterns in addition to type-level RBAC defaults.
- **Role precedence (team vs. tenant):** additive — a user's effective permissions are the union of tenant-level and team-level role grants. There is no override/deny semantics between scopes in Phase 1 (explicit deny/ACL exceptions are handled separately via the ACL layer, not via scope precedence).
- **ACL storage model:** hybrid — PostgreSQL is the source of truth for a sparse `(subject, resource_type, resource_id, permission)` ACL table; Redis/OPA's data cache serves hot reads for the authorization hot path, invalidated on write, to keep resource-instance checks within the sub-100ms budget.
- **Signup abuse prevention:** self-service tenant signup requires email verification before activation, is rate-limited per IP/email, is protected by CAPTCHA on the signup form, and new tenants land in a pending state pending manual operator review before full activation (belt-and-suspenders combination of all four controls).
- **Accessibility:** best-effort accessibility practices for the Phase 2/3 React UIs (semantic HTML, keyboard navigation, reasonable contrast), with no formal WCAG compliance target committed for Phase 1–3.
- **Custom domains:** required — tenants can use their own domain for hosted login/consent pages, not just a shared Hoviyat domain.
- **IdP role:** Hoviyat acts as both a relying party (consuming Google/GitHub OAuth2, generic OIDC, and SAML 2.0 for login) and an identity provider — third-party apps can integrate "Login with Hoviyat" via OAuth2/OIDC, requiring standard IdP capabilities (client/app registration, consent screens in Phase 3, token issuance to third parties, scopes/claims).
- **Hosting model:** self-hosted OSS only for Phases 1–3; no managed/hosted SaaS ("Hoviyat Cloud") is in scope.
- **IdP client registration:** self-service developer portal — any tenant admin (or a dedicated "developer" role, delegable via the granular admin-role system in §6) can register a third-party client app and receive a client_id/secret immediately, without platform-operator approval, mirroring the Google/GitHub OAuth app-registration model.
- **Tenant signup review:** near-instant, automated activation after email verification for the large majority of self-service signups. There is no blanket manual-review queue every tenant waits behind; instead, three concrete risk signals — disposable/temporary email domain detection (blocklist), IP reputation / known VPN-proxy-Tor detection, and tenant-creation velocity anomalies beyond the hard rate limit (§7) — route only flagged signups to manual platform-operator review, layered on top of the baseline rate limit + CAPTCHA + email verification (§6) that applies to every signup. This avoids the review queue becoming an onboarding bottleneck while keeping meaningful abuse controls for genuinely suspicious signups.
- **Default OAuth2/OIDC scopes/claims** for third-party client apps ("Login with Hoviyat", §9 IdP client registration): standard OIDC (`openid`, `profile`, `email`) plus two Hoviyat-specific custom claims — the user's roles/permissions within the tenant, and the tenant/org identifier — exposed by default so RBAC-aware and multi-org-aware third-party apps don't need a separate API call to get this context.
- **GDPR data export format** (Phase 3 self-service export): machine-readable JSON only — no bundled human-readable PDF/HTML summary in Phase 1–3.
- **Cache invalidation:** push-based invalidation on write. Every ACL/role/policy change immediately invalidates the relevant Redis/OPA cache entries (via pub/sub or direct delete) rather than relying on a TTL — chosen over TTL-based staleness because a revoked permission remaining honored for even a few seconds is unacceptable for a security-sensitive authorization system. This adds write-path complexity (the write must fan out invalidation before returning success) but keeps the sub-100ms read-path budget intact.
- **Phase 3 session management UX:** end users can (a) list their active sessions with device type, approximate location (IP geolocation), and last-active timestamp; (b) revoke an individual session/device; (c) "log out everywhere" — revoke all sessions except the current one in one action; and (d) receive an email alert on login from a new/unrecognized device or location.

**Non-engineering prerequisite:** a formal Terms of Service and Privacy Policy must be drafted (legal, not engineering scope) before self-service tenant signup (§6 Multi-tenancy) goes live in production — required given self-service signup collects PII and Phase 1 commits to GDPR handling (§6 Compliance & observability). This is tracked as a required deliverable, not merely a nice-to-have, and blocks production launch of self-service signup specifically (other Phase 1 functionality is not blocked by it).

## 10. Open questions

- Specific SAML/OIDC vendor quirks (Okta, Azure AD, Google Workspace) — deferred until a tenant requires one; will need per-vendor validation once identified.
- Audit log retention period: not yet specified — needs a decision (e.g. 1-year tenant-configurable vs. longer regulatory-grade window) before Phase 1's compliance features are complete.
- Custom domain TLS provisioning flow: exact ACME/cert-issuance mechanism and how quickly a newly-added custom domain becomes active.
- Exact risk-scoring thresholds/weighting for the signup risk signals (§9) — which signals combined, and how many, trigger manual review vs. outright rejection vs. silent pass — is an implementation-time tuning exercise, not a fixed PRD-level rule.

## 11. Licensing & project model

- **Open source:** public GitHub repository at https://github.com/arashrasoulzadeh/hoviyat under the **Apache-2.0** license — chosen over MIT for its explicit patent grant, given the enterprise SSO/SAML scope and potential patent-sensitive integrations.
- External contributions expected; repo should include CONTRIBUTING.md, issue/PR templates, and a code of conduct once Phase 1 implementation begins.

## 12. Success criteria / acceptance for Phase 1

Phase 1 is considered done when all of the following hold:
- Load/performance testing demonstrates the sub-100ms p99 authorization latency and the 99.9% uptime design.
- Chaos/failover testing (deliberate region/node failure injection) validates the RTO<5min/RPO<1min DR target under §7.
- Fuzz testing of REST/gRPC API inputs is run as part of the test suite, catching parsing/validation edge cases.
- Contract tests keep the Go SDK, OpenAPI spec, and gRPC/protobuf definitions in sync across versions, run in CI on every change to the API contracts.
- Automated test suite covers the full RBAC × ACL × ABAC decision matrix (role grants, resource-instance ACL overrides, OPA policy evaluation, and their combination via the unified decision API), including dedicated cross-tenant isolation tests (§7).
- A security audit / penetration test of the auth flows (password, OAuth2/OIDC, SAML, MFA, token issuance/revocation) is completed with no unresolved high/critical findings.
- At least one real internal or partner service integrates via the Go SDK/middleware and runs in production against Hoviyat.

## 13. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Aggressive <1-month timeline vs. Phase 1's broad scope (RBAC/ACL/ABAC, OAuth2/OIDC/SAML/MFA, IdP, passwordless, multi-region HA, full compliance) | Scope cut under deadline pressure, or shipped features under-tested | Sequence as a "walking skeleton" first (§13 Timeline); treat SSO/SAML, IdP mode, and full multi-region HA as fast-follow milestones rather than blocking the initial cut |
| OSS project + enterprise SSO/compliance complexity (SAML, GDPR, SOC2) attempted simultaneously with a new codebase | Slower velocity, higher defect risk in security-critical code reviewed by a wider (public) audience | Prioritize security audit (§12) before wide external contribution; keep enterprise SSO behind the generic-protocol-only decision (§9) rather than chasing vendor-specific integrations early |
| Self-service tenant signup abuse (spam tenants, fraud) despite risk-signal-based review (§9) | A small share of fraudulent tenants slip through automated activation, since most signups are no longer manually reviewed | Risk-signal thresholds/weighting are explicitly an implementation-time tuning exercise (§10), not fixed at PRD time — expect to iterate on false-negative/false-positive rates post-launch |
| Cross-tenant data leakage in a multi-tenant, row-scoped design | Severe: one tenant's data exposed to another, breaks the core trust model | Explicit, automated cross-tenant isolation tests as part of the Phase 1 acceptance criteria (§12), not just implicit in the schema design |
| Embedded OPA (in-process) policy evaluation cost at scale | Could threaten the sub-100ms p99 latency target under heavy ABAC policy load | Redis/OPA decision caching (§9 ACL storage model) and load testing against the latency SLO as a hard acceptance gate (§12) |
| Push-based cache invalidation (§9) adds write-path complexity/failure modes | A missed or delayed invalidation (e.g. pub/sub message dropped) could let a revoked permission remain honored longer than intended, undermining the security rationale for choosing push over TTL | Invalidation delivery should itself be monitored (§7 observability) with alerting on invalidation lag or failure, and covered by the fuzz/chaos testing already required (§12) |

## 14. Timeline

- Target: aggressive, **under 1 month** for a Phase 1 MVP, with a larger team allocated.
- Given the breadth of Phase 1 scope (multi-tenant RBAC/ACL/ABAC, OAuth2/OIDC/SAML/MFA, IdP + relying-party roles, passwordless, full audit/GDPR/SOC2, multi-region HA), a 1-month window is tight — recommend explicitly sequencing a "walking skeleton" (JWT auth + RBAC + REST API on one region) first, then layering ABAC/OPA, SSO/SAML, IdP mode, and multi-region HA as fast-follow milestones within or immediately after the same sprint, rather than treating all of Phase 1 as one atomic deliverable.

## 15. Milestones

| Phase | Deliverable | Target |
|---|---|---|
| Phase 1 | Backend auth/authz API (Go), PostgreSQL + Redis, OPA policy engine, REST/gRPC/SDK | < 1 month (aggressive) |
| Phase 2 | React admin panel | TBD |
| Phase 3 | React end-user front-end panel | TBD |
