# Insecure Design — Compact Remediation Guide

## What is Insecure Design?

Insecure design represents missing or ineffective security controls introduced during the design phase, before any code is written, requiring architectural changes rather than simple patches.

## STRIDE Mapping

- **Primary**: Spoofing (predictable tokens enable impersonation)
- **Secondary**: Information Disclosure (design flaws leak system state), Tampering (business logic bypass)

## Types/Patterns of Insecure Design

- **Predictable Tokens**: Sequential IDs, timestamp-based tokens allowing enumeration
- **Missing Rate Limiting**: Unlimited requests enabling brute force attacks
- **Token Expiration Failures**: Tokens valid indefinitely or for excessive periods
- **Reusable Tokens**: Password reset, session, or verification tokens usable multiple times
- **Business Logic Flaws**: Negative quantities, self-transfers, race conditions
- **No Defense in Depth**: Single security control with no backup layers

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Predictable token generation
export function generateResetToken(email: string): string {
  return email + Date.now(); // ❌ Predictable!
}

// ❌ VULNERABLE: No expiration, no rate limiting
const resetTokens = new Map<string, string>();

export function requestPasswordReset(email: string): string {
  const token = generateResetToken(email);
  resetTokens.set(token, email); // ❌ Never expires, can be reused
  return token;
}
// Attack: Attacker enumerates valid emails by generating predictable tokens
// Attack: Unlimited reset requests, brute force attempts, token reuse
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Cryptographically secure tokens with defense in depth
import crypto from 'crypto';
import bcrypt from 'bcrypt';

interface ResetToken {
  tokenHash: string;
  email: string;
  createdAt: Date;
  used: boolean;
}

const resetTokens = new Map<string, ResetToken>();
const rateLimits = new Map<string, number[]>();

const TOKEN_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes
const MAX_REQUESTS_PER_HOUR = 3;

// ✅ Rate limiting (defense layer 1)
function checkRateLimit(email: string): boolean {
  const now = Date.now();
  const attempts = (rateLimits.get(email) || [])
    .filter(time => time > now - 60 * 60 * 1000);

  if (attempts.length >= MAX_REQUESTS_PER_HOUR) {
    return false; // Rate limit exceeded
  }

  attempts.push(now);
  rateLimits.set(email, attempts);
  return true;
}

// ✅ Cryptographically secure token generation
export async function generateResetToken(email: string): Promise<string> {
  // ✅ Check rate limit
  if (!checkRateLimit(email)) {
    throw new Error('Please try again later');
  }

  // ✅ Generate 256-bit random token (defense layer 2)
  const token = crypto.randomBytes(32).toString('hex');

  // ✅ Hash token before storing (defense layer 3)
  const tokenHash = await bcrypt.hash(token, 10);

  // ✅ Store with expiration and usage tracking
  resetTokens.set(tokenHash, {
    tokenHash,
    email,
    createdAt: new Date(), // Defense layer 4: expiration
    used: false // Defense layer 5: one-time use
  });

  return token; // Send via email, only once
}

// ✅ Verify token with comprehensive checks
export async function verifyResetToken(token: string, email: string): Promise<boolean> {
  for (const [tokenHash, tokenData] of resetTokens.entries()) {
    const isMatch = await bcrypt.compare(token, tokenHash);

    if (isMatch && tokenData.email === email) {
      // ✅ Check expiration
      const tokenAge = Date.now() - tokenData.createdAt.getTime();
      if (tokenAge > TOKEN_EXPIRY_MS) {
        resetTokens.delete(tokenHash);
        throw new Error('Token expired');
      }

      // ✅ Check one-time use
      if (tokenData.used) {
        throw new Error('Token already used');
      }

      tokenData.used = true; // Mark as used
      return true;
    }
  }

  throw new Error('Invalid or expired token');
}

// ✅ Key Patterns:
// 1. crypto.randomBytes(32) generates unpredictable 256-bit tokens
// 2. Rate limiting prevents brute force (3 requests per hour)
// 3. Token hashing protects stored values from database breaches
// 4. Expiration limits attack window (30 minutes maximum)
// 5. One-time use prevents replay attacks even if token intercepted
```

## Human Review Checklist

- [ ] **Token Unpredictability** — All security tokens generated using crypto.randomBytes with minimum 32 bytes (256 bits), never derived from predictable sources like emails, usernames, or timestamps (test generate 100 tokens, verify no patterns or sequential values)

- [ ] **Token Expiration** — Every token has explicit expiration appropriate to use case (password reset 15-30 min, session hours/days), validated on every use (test create token, wait past expiration, verify rejection with generic error)

- [ ] **One-Time Token Usage** — Tokens for sensitive operations marked as used after successful verification, all subsequent attempts rejected (test use token successfully, attempt reuse and verify failure with logged security event)

- [ ] **Rate Limiting** — Rate limiting on all security-sensitive operations (password reset 3-5 per email per hour, login 5-10 per IP per 15 min), generic errors when exceeded (test make repeated requests until rate limit triggers, verify blocking with generic errors)

- [ ] **Token Storage Security** — Tokens never stored in plaintext, always hashed using bcrypt or SHA-256, verification uses constant-time comparison (test inspect token storage, verify only hashed tokens stored never plaintext)

- [ ] **Defense in Depth** — Multiple independent security layers implemented (cryptographic generation, hashing, expiration, one-time use, rate limiting, logging), each fails independently (test verify multiple protections exist, disabling one still leaves others protecting system)

---

**Key Takeaway**: Security must be designed in, not bolted on - use crypto.randomBytes for tokens, implement multiple independent security layers, and validate thoroughly at every step.
