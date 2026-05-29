# Security Logging and Monitoring Failures — Compact Remediation Guide

## What is Logging and Monitoring Failures?

Logging and monitoring failures allow attackers to remain undetected, escalate privileges, and extract data without proper security event logging, alerting, or forensic capability.

## STRIDE Mapping

- **Primary**: Repudiation (attackers deny actions due to lack of audit trail)
- **Secondary**: Information Disclosure (logs expose sensitive data like passwords or PII)

## Types/Patterns of Logging Failures

- **Logging Sensitive Data**: Passwords, tokens, API keys, credit cards in plaintext logs
- **No Security Event Logging**: Failed logins, access denials, privilege escalations not logged
- **Unstructured Logs**: Console.log with inconsistent formats difficult to parse
- **Missing Context**: Logs lack user ID, IP address, timestamp, or action details
- **No Alerting**: Security events logged but no real-time alerting to security team
- **Insufficient Retention**: Logs deleted too quickly for breach investigation
- **PII Exposure**: Email addresses, IPs logged in plaintext without masking

## What It Looks Like (TypeScript)

```typescript
// ❌ CRITICAL: Logs passwords and tokens in plaintext
export function login(email: string, password: string) {
  console.log('Login attempt', { email, password }); // ❌ Logs password!

  if (authenticate(email, password)) {
    const token = generateToken();
    console.log('Login successful', { email, token }); // ❌ Logs token!
    return token;
  }

  console.log('Login failed'); // ❌ Missing context: IP, timestamp
  return null;
}
// Attack: Passwords stored in logs accessible to anyone with log access
// Attack: No audit trail for privilege escalation or data deletion
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Structured logging with PII masking
import winston from 'winston';

// ✅ Configure structured logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json() // ✅ Structured JSON
  ),
  defaultMeta: { service: 'auth-service', environment: process.env.NODE_ENV },
  transports: [
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 30
    }),
    new winston.transports.File({
      filename: 'logs/security.log',
      level: 'warn',
      maxsize: 10485760,
      maxFiles: 90 // 90 days for compliance
    })
  ]
});

// ✅ Mask PII
function maskEmail(email: string): string {
  const [username, domain] = email.split('@');
  return `${username.charAt(0)}***@${domain}`;
}

function maskIP(ip: string): string {
  const parts = ip.split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.***` : `${parts[0]}:***`;
}

// ✅ Sanitize sensitive data
function sanitizeLogData(data: any): any {
  if (!data || typeof data !== 'object') return data;

  const sanitized = { ...data };

  // ✅ Remove sensitive fields entirely
  const sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'sessionId', 'creditCard'];
  for (const field of sensitiveFields) {
    if (field in sanitized) delete sanitized[field];
  }

  // ✅ Mask PII
  if (sanitized.email) sanitized.email = maskEmail(sanitized.email);
  if (sanitized.ipAddress) sanitized.ipAddress = maskIP(sanitized.ipAddress);

  return sanitized;
}

// ✅ Security event types
enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  LOGOUT = 'logout',
  ACCESS_DENIED = 'access_denied',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  USER_DELETED = 'user_deleted'
}

interface SecurityEvent {
  type: SecurityEventType;
  userId?: string;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  outcome: 'success' | 'failure';
  reason?: string;
}

// ✅ Track failed attempts for alerting
const failedLoginAttempts = new Map<string, number[]>();

// ✅ Determine if alert needed
function shouldAlert(event: SecurityEvent): boolean {
  const now = Date.now();

  // ✅ Alert on >5 failed logins from same IP in 5 min
  if (event.type === SecurityEventType.LOGIN_FAILURE && event.ipAddress) {
    const attempts = (failedLoginAttempts.get(event.ipAddress) || [])
      .filter(time => time > now - 5 * 60 * 1000);

    attempts.push(now);
    failedLoginAttempts.set(event.ipAddress, attempts);

    if (attempts.length > 5) return true;
  }

  // ✅ Alert on privilege escalation, access denied, user deletion
  if ([SecurityEventType.ACCESS_DENIED, SecurityEventType.USER_DELETED].includes(event.type)) {
    return true;
  }

  return false;
}

// ✅ Send security alert
async function sendSecurityAlert(logEntry: any): Promise<void> {
  console.error('🚨 SECURITY ALERT:', JSON.stringify(logEntry, null, 2));
  // Production: integrate Sentry, DataDog, PagerDuty, Slack
}

// ✅ Log security event with sanitization
export function logSecurityEvent(event: SecurityEvent): void {
  // ✅ Sanitize sensitive data
  const sanitized = sanitizeLogData(event);

  const logEntry = {
    timestamp: new Date().toISOString(),
    eventType: event.type,
    outcome: event.outcome,
    ...sanitized
  };

  // ✅ Log at appropriate level
  if (event.outcome === 'failure') {
    logger.warn('Security event', logEntry);
  } else {
    logger.info('Security event', logEntry);
  }

  // ✅ Send alert if critical
  if (shouldAlert(event)) {
    sendSecurityAlert(logEntry).catch(err => {
      logger.error('Failed to send alert', { error: err.message });
    });
  }
}

// ✅ Secure login logging
export function login(email: string, password: string, ipAddress: string, userAgent: string) {
  const user = authenticateUser(email, password);

  if (user) {
    // ✅ Log success (password NOT included, email/IP masked)
    logSecurityEvent({
      type: SecurityEventType.LOGIN_SUCCESS,
      userId: user.id,
      email, // Will be masked
      ipAddress, // Will be masked
      userAgent,
      outcome: 'success'
    });

    return generateToken(user.id);
  }

  // ✅ Log failure with context
  logSecurityEvent({
    type: SecurityEventType.LOGIN_FAILURE,
    email,
    ipAddress,
    userAgent,
    outcome: 'failure',
    reason: 'Invalid credentials'
  });

  return null;
}

// ✅ Key Patterns:
// 1. Structured JSON logging with Winston for easy parsing
// 2. Never log passwords, tokens, or secrets - remove entirely
// 3. Mask PII (emails to u***@domain, IPs to x.x.x.***)
// 4. Log all security events (auth, authz, validation failures)
// 5. Real-time alerting on suspicious patterns (>5 failed logins)
```

## Human Review Checklist

- [ ] **Structured Logging** — All logging uses Winston or similar with JSON format, never console.log, separate files for error/security logs with rotation (test grep codebase for console.log verify replaced, check logs are valid JSON with jq)

- [ ] **Sensitive Data Masking** — Passwords, tokens, API keys, session IDs never logged, PII masked (emails to u***@domain, IPs to x.x.x.***) (test search logs for literal passwords/tokens/full emails verify none exist, test sanitization function)

- [ ] **Security Event Logging** — All authentication/authorization events logged with context: user ID, masked email, masked IP, user agent, outcome, reason (test trigger events like failed login/access denied/validation error, verify all logged with complete context)

- [ ] **Contextual Metadata** — Every security log includes who/what/where/when/why: user identifier, resource, action, outcome, reason, timestamp in ISO 8601 (test review sample security logs verify they answer all W questions, verify request tracing works)

- [ ] **Real-Time Alerting** — Critical events trigger alerts (>5 failed logins in 5 min, privilege escalation, admin access denied), alerts delivered under 1 minute (test trigger alerting conditions, verify alerts delivered to Sentry/DataDog/PagerDuty/Slack)

- [ ] **Log Retention** — Logs retained minimum 30 days for general, 90 days for security (PCI-DSS compliance), automated rotation based on size/time (test verify log rotation creates new files at limits, check old logs compressed and deleted, verify retention period)

---

**Key Takeaway**: Detection capability is security capability - implement structured JSON logging, never log sensitive data, mask PII, log all security events with context, configure real-time alerting, and retain logs for forensic analysis.
