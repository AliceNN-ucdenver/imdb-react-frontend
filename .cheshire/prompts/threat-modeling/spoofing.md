# Spoofing Identity — Compact Remediation Guide

## What is Spoofing?

Spoofing occurs when attackers impersonate legitimate users, systems, or services by forging credentials, stealing session tokens, or bypassing authentication mechanisms, enabling unauthorized access to resources and data.

## Related OWASP

- **Primary**: A07 - Identification and Authentication Failures
- **Secondary**: A02 - Cryptographic Failures (weak secrets, insecure token generation)

## Types of Spoofing

- **Credential Theft**: Phishing, keylogging, credential stuffing with weak passwords
- **Session Hijacking**: Stealing or predicting session tokens (cookies, JWTs)
- **Token Replay**: Reusing captured authentication tokens
- **Weak Secrets**: Brute-forcing or guessing predictable tokens
- **MITM Attacks**: Intercepting credentials during transmission over insecure channels

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Hardcoded weak JWT secret exposed in client code
const SECRET = "supersecret123";
const token = jwt.sign({ userId: user.id, role: user.role }, SECRET);
// Attack: Attacker finds secret in JavaScript bundle, forges admin token

// ❌ VULNERABLE: Insecure session cookie without security flags
res.cookie("sessionId", sessionId, {
  maxAge: 86400000 // 24 hours, no HttpOnly/Secure flags
});
// Attack: Network attacker intercepts cookie over WiFi, steals session

// ❌ VULNERABLE: Predictable password reset token
const resetToken = `${Date.now()}_${userId}`;
await sendResetEmail(user.email, resetToken);
// Attack: Attacker enumerates timestamp+userId combinations to hijack accounts
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Strong authentication with cryptographic secrets
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcrypt";

// ✅ Key Pattern 1: Environment-based secrets with entropy validation
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be 32+ characters from secure random source");
}

// ✅ Key Pattern 2: Short-lived tokens with rotation
const accessToken = jwt.sign(
  { userId: user.id },
  JWT_SECRET,
  { algorithm: "HS256", expiresIn: "15m" }
);

// ✅ Key Pattern 3: Secure session cookies with all flags
res.cookie("sessionId", sessionId, {
  httpOnly: true,       // Prevent XSS access
  secure: true,         // HTTPS only
  sameSite: "strict",   // CSRF protection
  maxAge: 3600000       // 1 hour expiration
});

// ✅ Key Pattern 4: Cryptographically random reset tokens
const resetToken = crypto.randomBytes(32).toString("hex");
await db.query(
  "INSERT INTO reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
  [user.id, await bcrypt.hash(resetToken, 12), Date.now() + 900000] // 15 min
);

// ✅ Key Pattern 5: Rate limiting + account lockout
const failedAttempts = await redis.incr(`failed_login:${username}`);
if (failedAttempts > 5) {
  await redis.setex(`lockout:${username}`, 900, "1"); // 15 min lockout
  throw new Error("Account locked due to suspicious activity");
}
```

## Human Review Checklist

- [ ] **Credential Storage** — All passwords hashed with bcrypt at cost factor 12+ (validate no plaintext passwords in database, verify password complexity requirements enforced with 12+ character minimum)

- [ ] **Token Security** — JWT secrets stored in environment variables with 256+ bits entropy, never hardcoded (grep codebase for hardcoded secrets, verify tokens have expiration claims with 15-minute max for access tokens)

- [ ] **Session Management** — Session cookies use HttpOnly, Secure, and SameSite=Strict flags (inspect browser DevTools to verify flags present, test session regeneration after login, confirm session invalidation on logout)

- [ ] **Reset Flows** — Password reset tokens generated with crypto.randomBytes(32), single-use only, expire within 15 minutes (test token reuse is blocked, verify rate limiting at 5 requests/hour per email, check email notifications on password changes)

- [ ] **Multi-Factor Authentication** — MFA required for admin accounts and cannot be bypassed through alternate paths (attempt login without MFA and verify denial, test that password reset flow doesn't bypass MFA requirement)

- [ ] **Brute Force Protection** — Account lockout after 5 failed attempts, CAPTCHA after 3 attempts, distributed attack monitoring (simulate brute force with 10 incorrect passwords and verify lockout triggers, check alerts configured for suspicious authentication patterns)

---

**Key Takeaway**: Spoofing is prevented through strong cryptographic secrets, secure session management, and defense-in-depth authentication controls — always validate identity before granting access.
