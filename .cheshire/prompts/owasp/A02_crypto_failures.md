# Cryptographic Failures — Compact Remediation Guide

## What is Cryptographic Failures?

Cryptographic failures occur when applications fail to adequately protect sensitive data through encryption, including using weak algorithms, hardcoding secrets, or storing passwords in plaintext.

## STRIDE Mapping

- **Primary**: Information Disclosure (sensitive data exposed through weak encryption)
- **Secondary**: Tampering (lack of authenticated encryption allows data modification)

## Types/Patterns of Cryptographic Failures

- **Weak Encryption**: Using DES, 3DES, RC4, or MD5 instead of modern algorithms like AES-256-GCM
- **Hardcoded Secrets**: Encryption keys, passwords, or API keys stored in source code
- **Encoding vs Encryption**: Using base64 or hex encoding thinking it's encryption
- **Weak Password Hashing**: Using MD5, SHA1, or plaintext instead of bcrypt/Argon2
- **IV Reuse**: Using the same initialization vector for multiple encryptions
- **Missing TLS**: Transmitting sensitive data over HTTP instead of HTTPS

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Base64 encoding is not encryption!
export function encryptData(data: string): string {
  const key = "hardcoded-secret-key-123"; // ❌ Hardcoded key
  return Buffer.from(data + key).toString('base64'); // ❌ Just encoding
}

// ❌ VULNERABLE: Plaintext password storage
export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex'); // ❌ MD5 is broken
}
// Attack: Database breach exposes all passwords, MD5 easily rainbow-tabled
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: AES-256-GCM with proper key management
import crypto from 'crypto';
import bcrypt from 'bcrypt';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const BCRYPT_ROUNDS = 12;

// ✅ Load key from environment
function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;
  if (!key || Buffer.from(key, 'hex').length !== 32) {
    throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex chars)');
  }
  return Buffer.from(key, 'hex');
}

// ✅ Encrypt with authenticated encryption
export function encryptData(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH); // ✅ Fresh IV each time
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag(); // ✅ Authentication tag

  // ✅ Combine IV + authTag + encrypted data
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

// ✅ Decrypt with integrity verification
export function decryptData(encryptedData: string): string {
  const buffer = Buffer.from(encryptedData, 'base64');
  const iv = buffer.subarray(0, IV_LENGTH);
  const authTag = buffer.subarray(IV_LENGTH, IV_LENGTH + 16);
  const encrypted = buffer.subarray(IV_LENGTH + 16);

  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
  decipher.setAuthTag(authTag); // ✅ Will throw if tampered

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString('utf8');
}

// ✅ Secure password hashing
export async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash); // ✅ Constant-time
}

// ✅ Key Patterns:
// 1. AES-256-GCM provides both confidentiality and authenticity
// 2. Fresh random IV generated for each encryption operation
// 3. Keys loaded from environment variables, never hardcoded
// 4. bcrypt with cost factor 12+ for password hashing
// 5. Constant-time comparison prevents timing attacks
```

## Human Review Checklist

- [ ] **Encryption Algorithm** — Only AES-256-GCM used for symmetric encryption, provides both confidentiality and authenticity (test encrypt data and verify output includes IV, auth tag, and ciphertext; tampering fails decryption)

- [ ] **Key Management** — All encryption keys from environment variables or secrets management, never hardcoded (test remove key from environment, app fails to start with clear error; verify no keys in Git history)

- [ ] **IV Generation** — Every encryption generates fresh random IV using crypto.randomBytes(16), IV prepended to ciphertext (test encrypt same plaintext twice, outputs completely different due to random IVs)

- [ ] **Password Hashing** — Passwords hashed with bcrypt using cost factor 12+, verification uses bcrypt.compare() for constant-time comparison (test hash same password twice, hashes differ due to random salt; bcrypt.compare works for valid/invalid)

- [ ] **Authenticated Encryption** — GCM mode provides authentication through auth tag, retrieved with cipher.getAuthTag() and set with decipher.setAuthTag() (test modify encrypted data before decryption, verify rejection with authentication failure error)

- [ ] **Data in Transit** — All network communication uses TLS 1.2+ for sensitive data, APIs reject HTTP requests or redirect to HTTPS (test attempt HTTP connection to sensitive endpoints, verify rejection or redirect)

---

**Key Takeaway**: Use strong algorithms (AES-256-GCM), proper key management (environment variables), secure password hashing (bcrypt cost 12+), and never confuse encoding with encryption.
