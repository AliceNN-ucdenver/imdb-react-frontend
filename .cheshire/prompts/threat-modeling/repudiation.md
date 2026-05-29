# Repudiation — Compact Remediation Guide

## What is Repudiation?

Repudiation occurs when attackers perform malicious actions and deny responsibility, enabled by missing audit logs, insufficient logging detail, or log tampering that prevents forensic investigation and accountability.

## Related OWASP

- **Primary**: A09 - Security Logging and Monitoring Failures
- **Secondary**: A08 - Software and Data Integrity Failures (log integrity)

## Types of Repudiation

- **Missing Audit Logs**: No record of security-relevant actions like user deletions or privilege changes
- **Log Tampering**: Attacker modifies or deletes logs to erase evidence
- **Insufficient Context**: Logs lack critical details (IP, user ID, timestamp)
- **Unauthenticated Actions**: Anonymous operations with no identity binding
- **Log Injection**: Attacker pollutes logs with fake entries to obfuscate attacks

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: No audit logging for destructive admin action
app.delete("/api/admin/users/:id", isAdmin, async (req, res) => {
  await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.json({ success: true }); // No log of who deleted or when!
});
// Attack: Malicious admin deletes competitor's account, denies involvement with no evidence

// ❌ VULNERABLE: Logs stored locally where app can modify
const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: "app.log" })
  ]
});
// Attack: Attacker compromises server, deletes logs covering their tracks

// ❌ VULNERABLE: Minimal authentication logging without context
app.post("/api/auth/login", async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);

  if (!user) {
    logger.info("Login failed"); // No IP, username, or timestamp context
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json({ token: generateToken(user) });
});
// Attack: Brute force attack undetectable, no IP blocking possible
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Comprehensive audit logging with immutability
import winston from "winston";
import WinstonCloudWatch from "winston-cloudwatch";
import crypto from "crypto";

// ✅ Key Pattern 1: Structured logging to immutable external system
const auditLogger = winston.createLogger({
  format: winston.format.json(),
  transports: [
    // Send to CloudWatch (append-only, app cannot modify)
    new WinstonCloudWatch({
      logGroupName: "/app/audit",
      logStreamName: `${process.env.HOSTNAME}-${Date.now()}`,
      awsRegion: "us-east-1"
    })
  ]
});

// ✅ Key Pattern 2: Comprehensive context in all security events
app.delete("/api/admin/users/:id", isAdmin, async (req, res) => {
  const userId = req.params.id;

  // Fetch details before deletion for audit trail
  const user = await db.query(
    "SELECT username, email FROM users WHERE id = $1",
    [userId]
  );

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  await db.query("DELETE FROM users WHERE id = $1", [userId]);

  // Log with complete forensic context
  auditLogger.info({
    event: "user_deleted",
    actor: {
      userId: req.user.id,
      username: req.user.username,
      role: req.user.role
    },
    target: {
      userId: user.id,
      username: user.username,
      email: user.email
    },
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    requestId: req.id
  });

  res.json({ success: true });
});

// ✅ Key Pattern 3: Cryptographic log integrity
auditLogger.on("data", (info) => {
  // Sign each log entry to detect tampering
  const signature = crypto
    .createHmac("sha256", process.env.LOG_SIGNING_KEY)
    .update(JSON.stringify(info))
    .digest("hex");

  info.signature = signature;
});

// ✅ Key Pattern 4: Authentication logging with anomaly detection
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  const logContext = {
    username,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    timestamp: new Date().toISOString(),
    requestId: req.id,
    geolocation: await geolocateIP(req.ip)
  };

  const user = await authenticateUser(username, password);

  if (!user) {
    auditLogger.warn({
      event: "login_failed",
      reason: "invalid_credentials",
      ...logContext
    });

    // Increment failed attempt counter
    await redis.incr(`failed_login:${req.ip}`);

    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check for suspicious patterns
  if (await isAnomalousLogin(user.id, req.ip)) {
    auditLogger.warn({
      event: "anomalous_login",
      userId: user.id,
      reason: "new_location",
      ...logContext
    });

    await sendSecurityAlert(user.email, logContext);
  }

  auditLogger.info({
    event: "login_success",
    userId: user.id,
    ...logContext
  });

  res.json({ token: generateToken(user) });
});

// ✅ Key Pattern 5: PII masking in logs
function sanitizeForLogging(data: any): any {
  return {
    ...data,
    password: undefined, // Never log passwords
    ssn: data.ssn ? `***-**-${data.ssn.slice(-4)}` : undefined,
    creditCard: data.creditCard ? `****-${data.creditCard.slice(-4)}` : undefined
  };
}
```

## Human Review Checklist

- [ ] **Audit Coverage** — All security-relevant actions logged including authentication, authorization changes, data modifications, and admin operations (perform sensitive action like password reset and verify log entry with complete context, test that logs answer who/what/when/where/how)

- [ ] **Log Immutability** — Audit logs stored in append-only systems that application cannot modify or delete (attempt to modify log entry from application and verify access denial, check logs sent to CloudWatch/Splunk with IAM policies preventing write access, validate HMAC signatures on log entries)

- [ ] **Retention Compliance** — Logs retained for required durations: 90 days minimum for SOC 2, 1 year for PCI DSS (review retention settings in logging platform, verify automated archival to cold storage after active period, confirm deletion configured after compliance window expires)

- [ ] **Sensitive Data Masking** — Passwords, tokens, credit cards, SSNs never logged even in debug mode (submit request with credit card and verify only last 4 digits appear in logs, check password never appears in authentication failure logs, search logs for sensitive data patterns)

- [ ] **Real-Time Alerting** — High-severity security events trigger immediate alerts to security teams (simulate brute force with 10 failed logins and verify alert sent within 30 seconds, test alerts include actionable context for triage, check alert rules cover privilege escalation and anomalous data access)

- [ ] **Correlation and Tracing** — Each request includes correlation ID linking related events across microservices (generate request ID at ingress and verify propagation through all downstream logs, test searching for specific request ID shows complete event chain, validate structured JSON logging with consistent field names)

---

**Key Takeaway**: Repudiation is prevented through comprehensive, immutable audit logging — if you can't prove an action occurred with cryptographically signed logs, assume it didn't happen.
