# Identification and Authentication Failures — Compact Remediation Guide

## What is Authentication Failures?

Authentication failures allow attackers to assume other users' identities through weak password requirements, no brute force protection, or insecure session management.

## STRIDE Mapping

- **Primary**: Spoofing (attackers impersonate legitimate users)
- **Secondary**: Elevation of Privilege (gaining admin access through authentication bypass), Repudiation (no audit trail)

## Types/Patterns of Authentication Failures

- **Plaintext Passwords**: Storing passwords without hashing or using weak hashing (MD5, SHA-1)
- **Timing Attacks**: Non-constant-time password comparison leaking information
- **No Brute Force Protection**: Unlimited login attempts allowing password guessing
- **Weak Session Management**: Predictable session IDs or sessions that never expire
- **No Multi-Factor Authentication**: Relying solely on password without additional verification
- **Credential Stuffing**: No rate limiting or breach detection for automated credential testing

## What It Looks Like (TypeScript)

```typescript
// ❌ CRITICAL: Plaintext password and timing attack
const users = new Map<string, { email: string; password: string }>();

export function register(email: string, password: string) {
  users.set(email, { email, password }); // ❌ Plaintext!
}

export function login(email: string, password: string): boolean {
  const user = users.get(email);
  if (!user) return false;

  return user.password === password; // ❌ Non-constant-time!
}
// Attack: Database breach exposes all passwords
// Attack: Timing attack reveals if password is close to correct
// Attack: Unlimited brute force attempts
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: bcrypt, rate limiting, session management
import bcrypt from 'bcrypt';
import crypto from 'crypto';

const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;
const SESSION_IDLE_TIMEOUT = 30 * 60 * 1000;

interface User {
  id: string;
  email: string;
  passwordHash: string;
  failedAttempts: number;
  lockedUntil?: Date;
}

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const rateLimits = new Map<string, number[]>();

// ✅ Validate password strength
function validatePasswordStrength(password: string): void {
  if (password.length < 12) throw new Error('Password too short');
  if (!/[a-z]/.test(password)) throw new Error('Need lowercase');
  if (!/[A-Z]/.test(password)) throw new Error('Need uppercase');
  if (!/[0-9]/.test(password)) throw new Error('Need numbers');
  if (!/[^a-zA-Z0-9]/.test(password)) throw new Error('Need special chars');
}

// ✅ Register with bcrypt hashing
export async function registerUser(email: string, password: string): Promise<User> {
  validatePasswordStrength(password);

  // ✅ Hash with bcrypt cost factor 12
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  const user: User = {
    id: crypto.randomBytes(16).toString('hex'),
    email,
    passwordHash, // ✅ Store hash, not plaintext
    failedAttempts: 0
  };

  users.set(email, user);
  return user;
}

// ✅ Rate limiting
function checkRateLimit(identifier: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const attempts = (rateLimits.get(identifier) || [])
    .filter(time => time > now - windowMs);

  if (attempts.length >= maxRequests) return false;

  attempts.push(now);
  rateLimits.set(identifier, attempts);
  return true;
}

// ✅ Secure login with protections
export async function login(
  email: string,
  password: string,
  ipAddress: string
): Promise<{ sessionId: string } | null> {
  // ✅ Rate limiting by IP
  if (!checkRateLimit(ipAddress, 5, 15 * 60 * 1000)) {
    throw new Error('Too many login attempts');
  }

  const user = users.get(email);
  if (!user) {
    // ✅ Consume time even when user doesn't exist (prevent timing)
    await bcrypt.hash(password, BCRYPT_ROUNDS);
    throw new Error('Invalid credentials');
  }

  // ✅ Check account lockout
  if (user.lockedUntil && new Date() < user.lockedUntil) {
    throw new Error('Invalid credentials'); // ✅ Generic error
  }

  // ✅ Constant-time password verification
  const isValidPassword = await bcrypt.compare(password, user.passwordHash);

  if (!isValidPassword) {
    user.failedAttempts++;

    // ✅ Lock after 5 failed attempts
    if (user.failedAttempts >= MAX_LOGIN_ATTEMPTS) {
      user.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
    }

    throw new Error('Invalid credentials');
  }

  // ✅ Reset on success
  user.failedAttempts = 0;
  user.lockedUntil = undefined;

  // ✅ Generate cryptographically secure session ID
  const sessionId = crypto.randomBytes(32).toString('hex');

  sessions.set(sessionId, {
    id: sessionId,
    userId: user.id,
    createdAt: new Date(),
    lastAccessedAt: new Date(),
    ipAddress
  });

  return { sessionId };
}

// ✅ Validate session with expiration
export function validateSession(sessionId: string): { userId: string } | null {
  const session = sessions.get(sessionId);
  if (!session) return null;

  const now = new Date();

  // ✅ Check idle timeout (30 minutes)
  const idleTime = now.getTime() - session.lastAccessedAt.getTime();
  if (idleTime > SESSION_IDLE_TIMEOUT) {
    sessions.delete(sessionId);
    return null;
  }

  // ✅ Update last accessed
  session.lastAccessedAt = now;
  return { userId: session.userId };
}

// ✅ Key Patterns:
// 1. bcrypt with cost factor 12+ for password hashing
// 2. Constant-time comparison with bcrypt.compare() prevents timing attacks
// 3. Rate limiting (5 attempts/15 min) and account lockout (5 failures)
// 4. Cryptographically secure session IDs with crypto.randomBytes(32)
// 5. Session expiration (30 min idle, 24 hr absolute)
```

## Human Review Checklist

- [ ] **Password Storage** — All passwords hashed using bcrypt with cost factor 12+, never plaintext or weak algorithms (test inspect database verify only bcrypt hashes, register with same password twice verify different hashes)

- [ ] **Timing Attack Prevention** — Password verification uses bcrypt.compare() for constant-time comparison, failed logins consume similar time (test measure response time for wrong password vs wrong user, times should be similar within ~10ms)

- [ ] **Brute Force Protection** — Multi-layered protection: IP-based rate limiting (5 per 15 min) and per-account lockout (5 consecutive failures = 15 min lock) (test make 6 attempts from same IP verify 6th blocked, 5 wrong passwords verify account locks)

- [ ] **Session Management** — Session IDs generated using crypto.randomBytes(32), both idle timeout (30 min) and absolute timeout (24 hr) implemented (test login verify session works, wait 31 min idle verify expired, wait 25 hours verify expired)

- [ ] **Secure Cookies** — Session cookies have httpOnly flag, secure flag in production, sameSite attribute set to 'strict' or 'lax' (test inspect cookies in DevTools verify httpOnly, secure, sameSite flags, attempt JavaScript access verify undefined)

- [ ] **Generic Error Messages** — All authentication failures return identical generic "Invalid credentials" error for wrong password/username/locked account (test login with wrong user/password/locked account verify identical error with similar response times)

---

**Key Takeaway**: Never store plaintext passwords - use bcrypt (cost 12+), implement rate limiting and account lockout, use cryptographically secure session IDs, and enforce session expiration.
