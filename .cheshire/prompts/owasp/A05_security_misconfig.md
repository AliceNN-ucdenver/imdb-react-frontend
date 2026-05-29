# Security Misconfiguration — Compact Remediation Guide

## What is Security Misconfiguration?

Security misconfiguration arises from improper or insecure configuration of applications, frameworks, servers, and cloud services, often due to insecure defaults or lack of hardening.

## STRIDE Mapping

- **Primary**: Information Disclosure (verbose errors expose internals)
- **Secondary**: Tampering (permissive CORS enables CSRF), Elevation of Privilege (default credentials grant admin access)

## Types/Patterns of Security Misconfiguration

- **Permissive CORS**: Wildcard `*` origins allowing any website to make requests
- **Missing Security Headers**: No CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Verbose Error Messages**: Stack traces and internal paths exposed to clients
- **Default Credentials**: Admin/admin, unchanged API keys, example passwords
- **Debug Mode in Production**: Verbose logging, debug endpoints enabled
- **Server Information Leakage**: X-Powered-By header revealing framework

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Permissive CORS and no security headers
import express from 'express';
import cors from 'cors';

const app = express();

app.use(cors({ origin: '*' })); // ❌ Allows requests from ANY origin

// ❌ No security headers configured

app.use((err: Error, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack // ❌ Exposes stack trace!
  });
});
// Attack: Any website can make authenticated requests (CSRF)
// Attack: Stack traces reveal internal structure and file paths
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Restrictive CORS, security headers, safe error handling
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ✅ Domain allowlist from environment
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map(origin => origin.trim());

// ✅ Restrictive CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // Allow non-browser clients

    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('CORS blocked', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  exposedHeaders: ['Content-Length', 'X-Request-Id']
}));

// ✅ Comprehensive security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:']
    }
  },
  strictTransportSecurity: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true
  },
  frameguard: { action: 'deny' },
  noSniff: true
}));

// ✅ Disable X-Powered-By
app.disable('x-powered-by');

// ✅ Safe error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  // ✅ Log full error server-side only
  console.error('Application error:', {
    message: err.message,
    stack: IS_PRODUCTION ? undefined : err.stack,
    url: req.url
  });

  // ✅ Generic response in production
  if (IS_PRODUCTION) {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ✅ Environment-specific configuration
const config = {
  port: parseInt(process.env.PORT || '3000'),
  database: {
    host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD // ❌ Never hardcode
  },
  session: {
    secret: process.env.SESSION_SECRET,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION, // HTTPS only in production
      sameSite: 'strict' as const
    }
  }
};

// ✅ Key Patterns:
// 1. Explicit origin allowlist, never wildcard *
// 2. Comprehensive security headers with helmet.js (CSP, HSTS, X-Frame-Options)
// 3. Generic error messages in production, detailed only in development
// 4. Environment variables for all sensitive config, never hardcoded
// 5. Secure cookie flags (httpOnly, secure, sameSite) prevent XSS and CSRF
```

## Human Review Checklist

- [ ] **CORS Configuration** — Explicit allowlist of permitted origins, never wildcard * (test attempt requests from allowed origin succeed, non-allowed origin fail with CORS error)

- [ ] **Security Headers** — Comprehensive headers using helmet.js: CSP restricts resources, HSTS enforces HTTPS, X-Frame-Options prevents clickjacking, X-Content-Type-Options prevents MIME sniffing (test use browser DevTools or curl to verify all headers present with correct values)

- [ ] **Error Handling** — Error responses environment-aware, generic messages in production never exposing stack traces or internal details (test trigger errors in production mode, verify generic messages to client and full details in server logs)

- [ ] **Environment Configuration** — Configuration externalized to environment variables, different .env files for dev/prod never committed to version control (test run application without required variables, verify clear error message and failure)

- [ ] **Cookie Security** — Session cookies have httpOnly flag, secure flag in production, sameSite attribute set to 'strict' or 'lax' (test inspect cookies in browser DevTools, verify httpOnly, secure, and sameSite flags set correctly)

- [ ] **Credential Management** — Never hardcode credentials, API keys, or secrets in source code, all from environment variables or vault (test search codebase for patterns like "password=", "apiKey:", verify no hardcoded values)

---

**Key Takeaway**: Configuration is code and must be reviewed with the same rigor - use restrictive CORS, comprehensive security headers, safe error handling, and environment-specific configuration.
