# Information Disclosure — Compact Remediation Guide

## What is Information Disclosure?

Information disclosure occurs when attackers gain unauthorized access to sensitive data through broken access controls, verbose error messages, unencrypted storage, or oversharing APIs, compromising data confidentiality.

## Related OWASP

- **Primary**: A01 - Broken Access Control (IDOR, unauthorized data access)
- **Secondary**: A02 - Cryptographic Failures (unencrypted data, weak crypto)

## Types of Information Disclosure

- **IDOR Vulnerabilities**: Accessing other users' data by manipulating resource IDs
- **Verbose Error Messages**: Stack traces exposing file paths, database schemas, credentials
- **Unencrypted Storage**: Plaintext data in databases, backups, or file systems
- **API Over-sharing**: Endpoints returning more fields than necessary
- **Cryptographic Failures**: Weak encryption, exposed keys, plaintext transmission

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: IDOR allowing access to any user's profile
app.get("/api/users/:userId/profile", isAuthenticated, async (req, res) => {
  const profile = await db.query(
    "SELECT * FROM users WHERE id = $1",
    [req.params.userId]
  );
  res.json(profile); // Returns other users' SSN, address, phone!
});
// Attack: Change userId from 123 to 124 in URL, scrape all user data

// ❌ VULNERABLE: Verbose production error messages
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Exposes file paths and structure!
    query: err.query  // Reveals database schema!
  });
});
// Attack: Send malformed request, learn PostgreSQL version and file structure

// ❌ VULNERABLE: Unencrypted database backup to public S3
pg_dump -U postgres mydb > /tmp/backup.sql
aws s3 cp /tmp/backup.sql s3://my-company-backups/ --acl public-read
// Attack: Enumerate S3 buckets, download plaintext backup with all user data
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Multi-layer confidentiality protection
import { z } from "zod";
import { S3Client, GetBucketAclCommand } from "@aws-sdk/client-s3";

// ✅ Key Pattern 1: Authorization + data minimization
app.get("/api/users/:userId/profile", isAuthenticated, async (req, res) => {
  const requestedUserId = parseInt(req.params.userId);

  // Verify user can only access their own profile
  if (req.user.id !== requestedUserId) {
    logger.warn({
      event: "idor_attempt",
      requestingUser: req.user.id,
      targetUser: requestedUserId,
      ip: req.ip
    });

    return res.status(403).json({ error: "Forbidden" });
  }

  // Return only necessary fields (no SSN, passwords, etc.)
  const profile = await db.query(
    "SELECT id, username, email, display_name FROM users WHERE id = $1",
    [requestedUserId]
  );

  if (!profile) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json(profile);
});

// ✅ Key Pattern 2: Generic error messages in production
app.use((err, req, res, next) => {
  // Log full details server-side for debugging
  logger.error({
    event: "unhandled_error",
    error: {
      message: err.message,
      stack: err.stack,
      code: err.code
    },
    request: {
      method: req.method,
      path: req.path,
      userId: req.user?.id,
      ip: req.ip
    },
    requestId: req.id
  });

  const statusCode = err.statusCode || 500;

  // Return generic error to client in production
  if (process.env.NODE_ENV === "production") {
    return res.status(statusCode).json({
      error: "Internal server error",
      requestId: req.id // For support ticket reference
    });
  }

  // Development only: include details
  res.status(statusCode).json({
    error: err.message,
    requestId: req.id
  });
});

// ✅ Key Pattern 3: Encrypted backups with access controls
// bash:
// pg_dump -U postgres mydb | \
//   gpg --symmetric --cipher-algo AES256 \
//     --passphrase "$BACKUP_ENCRYPTION_KEY" \
//     --batch --yes \
//   > /tmp/backup.sql.gpg
//
// aws s3 cp /tmp/backup.sql.gpg \
//   s3://my-company-backups-encrypted/backup-$(date +%Y%m%d).sql.gpg \
//   --server-side-encryption aws:kms \
//   --ssekms-key-id "$KMS_KEY_ID"

async function validateBackupBucket(bucketName: string): Promise<void> {
  const s3 = new S3Client({ region: "us-east-1" });

  const acl = await s3.send(new GetBucketAclCommand({
    Bucket: bucketName
  }));

  // Fail if bucket is public
  const isPublic = acl.Grants?.some(grant =>
    grant.Grantee?.URI?.includes("AllUsers") ||
    grant.Grantee?.URI?.includes("AuthenticatedUsers")
  );

  if (isPublic) {
    throw new Error("Backup bucket must not be public!");
  }

  logger.info("Backup bucket security validated", { bucketName });
}

// ✅ Key Pattern 4: Encryption at rest for sensitive data
import crypto from "crypto";

async function encryptPII(data: string): Promise<string> {
  const algorithm = "aes-256-gcm";
  const key = Buffer.from(process.env.ENCRYPTION_KEY, "hex"); // 32 bytes
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");

  const authTag = cipher.getAuthTag();

  // Store: iv:authTag:encrypted
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
}

// ✅ Key Pattern 5: TLS 1.3 with strong ciphers + HSTS
// nginx.conf:
// ssl_protocols TLSv1.3 TLSv1.2;
// ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
// ssl_prefer_server_ciphers on;
// add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

## Human Review Checklist

- [ ] **Access Control** — Every API endpoint returning user data verifies requesting user is authorized for that specific resource (test IDOR by logging in as User A and changing resource IDs to User B's data, verify 403 Forbidden responses, check centralized authorization middleware validates ownership)

- [ ] **Data Minimization** — APIs return only minimum necessary fields with explicit column selection, never SELECT * (inspect API responses for sensitive fields like SSN or full credit card numbers, verify separate schemas for admin vs user contexts, check database queries specify exact columns)

- [ ] **Error Handling** — Production never exposes stack traces, SQL queries, or file paths (send malformed requests and verify generic error messages only, test NODE_ENV=production disables verbose errors, confirm error monitoring tools capture details server-side)

- [ ] **Encryption at Rest** — All sensitive data encrypted in databases, backups, S3 buckets using AES-256-GCM with KMS key management (inspect database to verify encryption enabled, check S3 bucket has SSE-KMS configured, verify backup files are encrypted before upload, test raw data cannot be accessed without decryption keys)

- [ ] **Encryption in Transit** — All communication uses TLS 1.3 or 1.2 with HSTS headers and certificate pinning in mobile apps (scan with SSL Labs or testssl.sh for A+ rating, verify HSTS header with max-age=31536000, test WebSocket connections use WSS not WS, check internal service-to-service uses TLS)

- [ ] **Secrets Management** — No hardcoded API keys, passwords, or encryption keys in source code (search codebase with regex for common secret patterns, verify environment variables loaded from secure vaults like AWS Secrets Manager, test secret scanning in CI/CD with trufflehog, confirm secrets rotated quarterly)

---

**Key Takeaway**: Information disclosure is prevented by enforcing access control, encrypting sensitive data at rest and in transit, and minimizing data exposure — default to privacy and verify authorization on every request.
