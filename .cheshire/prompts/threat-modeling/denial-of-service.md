# Denial of Service — Compact Remediation Guide

## What is Denial of Service?

Denial of Service (DoS) occurs when attackers exhaust system resources or exploit design flaws to make services unavailable to legitimate users through resource exhaustion, algorithmic complexity attacks, or missing rate limits.

## Related OWASP

- **Primary**: A04 - Insecure Design (missing rate limits, algorithmic complexity)
- **Secondary**: A05 - Security Misconfiguration (resource limits, timeouts)

## Types of Denial of Service

- **Resource Exhaustion**: Consuming CPU, memory, disk, network bandwidth
- **Algorithmic Complexity**: Exploiting O(n²) algorithms with pathological inputs
- **ReDoS**: Catastrophic backtracking in regex patterns
- **Missing Rate Limits**: Unlimited API requests overwhelming servers
- **Amplification Attacks**: Small requests triggering large responses

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: User-controlled regex causing ReDoS
app.get("/api/search", async (req, res) => {
  const pattern = new RegExp(req.query.q, "i");
  const results = await db.query("SELECT * FROM products")
    .then(products => products.filter(p => pattern.test(p.name)));
  res.json(results);
});
// Attack: Input ^(a+)+$ with aaaaaaaaX causes catastrophic backtracking, 100% CPU

// ❌ VULNERABLE: Unbounded file upload exhausting disk
import multer from "multer";
const upload = multer({ dest: "/uploads" }); // No size limit!

app.post("/api/upload", upload.single("file"), (req, res) => {
  res.json({ success: true });
});
// Attack: Upload 10GB files repeatedly until disk full, service crashes

// ❌ VULNERABLE: No rate limiting on authentication endpoint
app.post("/api/auth/login", async (req, res) => {
  const user = await db.query("SELECT * FROM users WHERE username = $1", [req.body.username]);

  if (!user || !await bcrypt.compare(req.body.password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json({ token: generateToken(user) });
});
// Attack: 1000 concurrent login attempts exhaust database connections
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Multi-layer DoS prevention
import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import slowDown from "express-slow-down";
import Joi from "joi";
import { setTimeout } from "timers/promises";

// ✅ Key Pattern 1: Input validation preventing ReDoS
const searchSchema = Joi.object({
  q: Joi.string()
    .min(2).max(100)
    .regex(/^[a-zA-Z0-9\s-]+$/, "Alphanumeric only") // No regex metacharacters
    .required()
});

app.get("/api/search", async (req, res) => {
  // Validate input (reject special regex characters)
  const { q } = await searchSchema.validateAsync(req.query);

  // Use database full-text search (not regex)
  const timeoutPromise = setTimeout(5000, { timeout: true });

  const searchPromise = db.query(
    "SELECT id, name FROM products WHERE to_tsvector('english', name) @@ plainto_tsquery('english', $1) LIMIT 100",
    [q]
  );

  // Race with timeout
  const result = await Promise.race([searchPromise, timeoutPromise]);

  if (result.timeout) {
    return res.status(503).json({
      error: "Search timeout - try a more specific query"
    });
  }

  res.json(result);
});

// ✅ Key Pattern 2: File upload limits + quotas + validation
import multer from "multer";

const upload = multer({
  dest: "/uploads",
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }

    cb(null, true);
  }
});

app.post("/api/upload", isAuthenticated, async (req, res) => {
  // Check user quota
  const userStorage = await getUserStorageUsed(req.user.id);
  const quota = 100 * 1024 * 1024; // 100MB per user

  if (userStorage >= quota) {
    return res.status(403).json({ error: "Storage quota exceeded" });
  }

  // Rate limit: 5 uploads per minute per user
  const rateLimitKey = `upload:${req.user.id}`;
  const uploadCount = await redis.incr(rateLimitKey);

  if (uploadCount === 1) {
    await redis.expire(rateLimitKey, 60);
  }

  if (uploadCount > 5) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  upload.single("file")(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "File too large (max 10MB)" });
      }
      return res.status(400).json({ error: err.message });
    }

    await incrementUserStorage(req.user.id, req.file.size);
    res.json({ success: true, fileId: req.file.filename });
  });
});

// ✅ Key Pattern 3: Multi-layer rate limiting on authentication
const loginLimiter = rateLimit({
  store: new RedisStore({ client: redis }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: "Too many login attempts. Try again in 15 minutes.",
  standardHeaders: true
});

const loginSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 3,
  delayMs: 1000 // Add 1s delay after 3rd attempt
});

app.post("/api/auth/login",
  loginLimiter,
  loginSlowDown,
  async (req, res) => {
    const { username, password } = req.body;

    // Account-based lockout
    const lockoutKey = `lockout:${username}`;
    const isLocked = await redis.get(lockoutKey);

    if (isLocked) {
      return res.status(403).json({
        error: "Account locked due to suspicious activity"
      });
    }

    const user = await db.query(
      "SELECT id, password_hash FROM users WHERE username = $1",
      [username]
    );

    const validPassword = user ?
      await bcrypt.compare(password, user.password_hash) :
      await bcrypt.hash(password, 12); // Prevent user enumeration

    if (!user || !validPassword) {
      // Increment failed attempts
      const failedKey = `failed:${username}`;
      const failedCount = await redis.incr(failedKey);
      await redis.expire(failedKey, 3600);

      // Lock after 10 failures
      if (failedCount >= 10) {
        await redis.setex(lockoutKey, 3600, "1");
        await sendAccountLockoutEmail(username);
      }

      return res.status(401).json({ error: "Invalid credentials" });
    }

    await redis.del(`failed:${username}`);
    res.json({ token: generateToken(user) });
  }
);

// ✅ Key Pattern 4: Database query timeouts + pagination
// PostgreSQL: SET statement_timeout = '5s';
// All list endpoints: LIMIT 100, OFFSET pagination

// ✅ Key Pattern 5: Monitoring + auto-scaling
// - Alert on CPU >80%, memory >85%, p95 latency >500ms
// - Distributed tracing to identify slow operations
// - Auto-scaling groups respond to traffic spikes
```

## Human Review Checklist

- [ ] **Rate Limiting** — Every public API endpoint has rate limiting configured with stricter limits for critical endpoints like login and search (test sending 100 rapid requests and verify 429 Too Many Requests after threshold, check Redis stores rate counters for distributed systems, validate sliding windows used instead of fixed windows)

- [ ] **Timeouts and Circuit Breakers** — All external calls have timeouts: 5-10 seconds for database queries, 3-5 seconds for HTTP requests (simulate slow database by adding delays and verify requests timeout instead of hanging indefinitely, test circuit breakers stop calling failing services after N consecutive failures, check exponential backoff on retries)

- [ ] **Resource Limits** — File sizes limited to 10MB, pagination enforced with max 1000 results per page, memory and CPU limits set (attempt to upload file larger than limit and verify rejection, query list endpoint without pagination and verify default page size applied, check Node.js --max-old-space-size configured)

- [ ] **Input Complexity Validation** — User inputs cannot affect algorithmic complexity: reject regex metacharacters, limit search query length to 100 characters, use allowlist for sort fields (submit pathological regex like ^(a+)+$ and verify rejection using safe-regex library, test database full-text search used instead of application-side filtering)

- [ ] **Database Optimization** — All queries have EXPLAIN plans reviewed, indexes on frequently queried columns, N+1 queries avoided (run EXPLAIN on all queries and verify index usage, check slow query log for queries >100ms, validate pagination uses LIMIT/OFFSET with indexed columns)

- [ ] **Monitoring and Alerting** — Metrics collected for CPU, memory, disk, request latency, alerts configured for abnormal patterns (verify dashboards show resource usage trends, test alerts fire when CPU >80% or p95 latency >500ms, check auto-scaling responds to traffic spikes, simulate high load to validate DoS protections)

---

**Key Takeaway**: Denial of Service is prevented by rate limits, timeouts, and resource quotas — design for graceful degradation where services fail safely under load, not catastrophically.
