# Tampering with Data — Compact Remediation Guide

## What is Tampering?

Tampering occurs when attackers maliciously modify data, code, or system configurations without authorization, compromising data integrity through injection attacks, parameter manipulation, or artifact modification.

## Related OWASP

- **Primary**: A03 - Injection (SQL, command, LDAP injection)
- **Secondary**: A08 - Software and Data Integrity Failures (unsigned code, unverified updates)

## Types of Tampering

- **SQL Injection**: Manipulating database queries to modify or delete data
- **Parameter Tampering**: Changing prices, quantities, permissions in API requests
- **Code Injection**: Inserting malicious commands into application inputs
- **MITM Modification**: Intercepting and altering network traffic
- **Artifact Manipulation**: Replacing deployment binaries or Docker images with compromised versions

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: SQL injection via string concatenation
app.get("/api/users/search", (req, res) => {
  const query = `SELECT * FROM users WHERE username='${req.query.username}'`;
  db.query(query, (err, results) => res.json(results));
});
// Attack: Input admin'; UPDATE users SET role='admin' WHERE id=1-- elevates privileges

// ❌ VULNERABLE: Client-controlled price in checkout
app.post("/api/orders/checkout", async (req, res) => {
  const { productId, price } = req.body;
  await processPayment(price); // Uses attacker's price!
  res.json({ success: true });
});
// Attack: Attacker changes {"price": 100} to {"price": 1} and buys $100 item for $1

// ❌ VULNERABLE: Unsigned deployment artifact
deploy:
  script:
    - docker pull myregistry/app:latest
    - docker run myregistry/app:latest
// Attack: Attacker replaces image in registry with backdoored version
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Multi-layer tampering prevention
import { z } from "zod";
import crypto from "crypto";

// ✅ Key Pattern 1: Parameterized queries with input validation
const searchSchema = z.object({
  username: z.string()
    .min(3).max(50)
    .regex(/^[a-zA-Z0-9_-]+$/, "Alphanumeric only")
});

app.get("/api/users/search", async (req, res) => {
  const { username } = searchSchema.parse(req.query);

  // Use parameterized query (driver escapes safely)
  const results = await db.query(
    "SELECT id, username, email FROM users WHERE username = $1",
    [username]
  );

  res.json(results);
});

// ✅ Key Pattern 2: Server-side business logic enforcement
app.post("/api/orders/checkout", async (req, res) => {
  const { productId, quantity } = req.body;

  // Fetch authoritative price from database (never trust client)
  const product = await db.query(
    "SELECT price FROM products WHERE id = $1",
    [productId]
  );

  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  // Calculate price server-side
  const totalPrice = product.price * quantity;

  await processPayment(totalPrice);
  res.json({ success: true, charged: totalPrice });
});

// ✅ Key Pattern 3: Cryptographic integrity verification
async function verifyWebhookSignature(req: Request): Promise<boolean> {
  const signature = req.headers["x-webhook-signature"];
  const payload = JSON.stringify(req.body);

  const expectedSignature = crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(payload)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// ✅ Key Pattern 4: Artifact signing in CI/CD
// build:
//   script:
//     - docker build -t myregistry/app:${CI_COMMIT_SHA} .
//     - docker push myregistry/app:${CI_COMMIT_SHA}
//     - cosign sign --key cosign.key myregistry/app:${CI_COMMIT_SHA}
//
// deploy:
//   script:
//     - cosign verify --key cosign.pub myregistry/app:${CI_COMMIT_SHA}
//     - docker pull myregistry/app:${CI_COMMIT_SHA}

// ✅ Key Pattern 5: Database least privilege + audit logging
// Query user has SELECT only, no UPDATE/DELETE
// Separate admin account for schema changes
// Audit trigger logs all modifications with user, timestamp, old/new values
```

## Human Review Checklist

- [ ] **Input Validation** — All user inputs validated with allowlist schemas defining type, length, format, and allowed characters (grep for string concatenation in SQL queries, test SQL injection payloads like ' OR '1'='1, verify parameterized statements used throughout)

- [ ] **Server-Side Logic** — Business-critical values like prices, permissions, and roles calculated server-side from authoritative sources (test modifying request payloads with Burp Suite, attempt to change prices to $0 or user IDs to other accounts, verify server rejects client-provided security values)

- [ ] **Code Integrity** — Deployment artifacts signed with cryptographic signatures and verified before execution (attempt to deploy unsigned image and verify rejection, check SRI hashes on CDN scripts in HTML, confirm package lockfiles committed)

- [ ] **Transport Security** — All communication uses TLS 1.3 with certificate pinning, webhooks validate HMAC signatures (test MITM attack with mitmproxy, verify TLS connections fail on invalid certificates, check webhook signatures are validated)

- [ ] **Database Controls** — Application database accounts have minimal privileges with read-only access where possible (review database user permissions, verify query accounts lack UPDATE/DELETE on sensitive tables, test executing privileged queries through app fails)

- [ ] **Audit Logging** — All data modifications logged with who, what, when, where details to immutable append-only systems (perform data change and verify audit log entry appears with complete context, test that application cannot modify or delete logs, confirm row-level versioning enabled)

---

**Key Takeaway**: Tampering is prevented by validating all inputs, enforcing business logic server-side, and cryptographically verifying integrity — never trust data you didn't create or sign.
