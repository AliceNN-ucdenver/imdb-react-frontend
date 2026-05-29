# Security-First Baseline — Always Applied

You are implementing a feature for a governed business application. Follow the
security-first baseline below. If a CALM architecture specification or threat
model is provided in this issue, review the controls defined there and ensure
your implementation satisfies them.

---

## CALM Architecture Controls

When CALM architecture data is present in this issue:
- Review every `control` attached to nodes and relationships
- Implement controls as coded enforcement (middleware, validators, policies) — not just comments
- Verify interface contracts match the CALM `interfaces` definition
- Ensure data classifications are respected (encryption, masking, access restrictions)

---

## OWASP Top 10 — Implementation Checklist

### A01: Broken Access Control
- Deny-by-default authorization middleware
- RBAC/ABAC with centralized role checks
- IDOR prevention: validate resource ownership on every request
- Restrictive CORS (no wildcard origins on authenticated endpoints)

### A02: Cryptographic Failures
- AES-256-GCM for encryption at rest, TLS 1.2+ in transit
- bcrypt (cost 12+) or Argon2 for password hashing
- Secrets via environment variables — never hardcode keys

### A03: Injection
- Parameterized queries ($1 placeholders) — no string concatenation
- Zod/Joi schema validation with allowlist regex on all inputs
- Output encoding for HTML contexts (XSS prevention)

### A04: Insecure Design
- Rate limiting on authentication and sensitive endpoints
- Cryptographically secure tokens for password reset, email verification
- Token expiration and single-use enforcement

### A05: Security Misconfiguration
- Security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- No debug/dev features in production code paths
- Environment-specific configuration (dev/staging/prod)

### A06: Vulnerable Components
- Dependency pinning with lockfiles (committed)
- No eval() or dynamic code execution with remote content
- Regular dependency updates (3-month freshness rule)

### A07: Authentication Failures
- bcrypt with constant-time comparison
- Secure session cookies: httpOnly, secure, sameSite=strict
- JWT with RS256 or EdDSA, short expiration, refresh token rotation

### A08: Integrity Failures
- HMAC-SHA256 signatures for build artifacts and deployments
- SRI on CDN assets, lockfile checksum verification

### A09: Logging & Monitoring
- Structured JSON logging for all security events
- PII/secret masking in log output
- Log auth events (login, logout, failed login, permission denied)

### A10: SSRF
- URL allowlisting (domain + protocol)
- Block private IP ranges (RFC1918, loopback, link-local)
- Block cloud metadata endpoints (169.254.169.254)

---

## STRIDE Threat Modeling — Build-Time Controls

| Threat | Control |
|--------|---------|
| **Spoofing** | Strong auth (JWT/OAuth2), MFA where required, secure session management |
| **Tampering** | Input validation on all boundaries, HMAC integrity checks, parameterized queries |
| **Repudiation** | Structured audit logging, tamper-evident logs, security event tracking |
| **Information Disclosure** | Encryption at rest/in transit, data classification enforcement, generic errors |
| **Denial of Service** | Rate limiting, input size limits, circuit breakers, resource quotas |
| **Elevation of Privilege** | Deny-by-default RBAC, least privilege, centralized authorization middleware |

---

## Maintainability — Code Quality Gates

- **Cyclomatic complexity ≤ 10** per function
- **Single Responsibility** — one reason to change per module
- **DRY** — no duplicate business logic; extract shared utilities
- **Dependency hygiene** — pin versions, audit regularly, remove unused deps
- **Fitness functions** — automated quality gates in CI
- **Test coverage ≥ 80%** — unit tests for business logic, integration tests for APIs
- **Write tests that verify security controls**, not just happy paths
