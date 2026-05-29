# DRY Principle — Compact Remediation Guide

## What is the DRY Principle?

The DRY (Don't Repeat Yourself) Principle states that every piece of knowledge must have a single, authoritative representation in the codebase; duplication creates maintenance burden where bugs must be fixed in N places instead of one.

## Related OWASP

- **Primary**: A07 - Authentication Failures (duplicated auth logic leads to inconsistent security controls)
- **Secondary**: A01 - Broken Access Control (authorization checks must be centralized to prevent bypass)

## Types/Patterns of Duplication

- **Code Duplication**: Identical or similar code blocks repeated across files (copy-paste anti-pattern)
- **Logic Duplication**: Same business rules implemented multiple times with subtle variations
- **Magic Numbers/Strings**: Hardcoded values (12, "admin", "api.example.com") repeated throughout codebase
- **Structural Duplication**: Similar patterns (try/catch + logging, validation + error handling) that could be abstracted
- **Configuration Duplication**: Same settings repeated in multiple files instead of single source
- **Validation Duplication**: Same validation rules implemented in multiple routes/services

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Duplicated validation logic in 15+ files
// File: src/routes/users.ts
app.post('/users', async (req, res) => {
  const errors = [];
  if (!req.body.email) errors.push('Email required');
  if (!req.body.email?.includes('@')) errors.push('Invalid email');
  if (!req.body.password) errors.push('Password required');
  if (req.body.password?.length < 12) errors.push('Password too short');
  if (errors.length > 0) return res.status(400).json({ errors });
  // ... create user
});

// File: src/routes/auth.ts (DUPLICATE LOGIC)
app.post('/login', async (req, res) => {
  const errors = [];
  if (!req.body.email) errors.push('Email required');
  if (!req.body.email?.includes('@')) errors.push('Invalid email');
  if (!req.body.password) errors.push('Password required');
  if (req.body.password?.length < 12) errors.push('Password too short');
  if (errors.length > 0) return res.status(400).json({ errors });
  // ... authenticate
});

// File: src/services/users.ts (MAGIC NUMBER)
if (password.length < 12) throw new Error('Password too short');

// File: tests/auth.test.ts (MAGIC NUMBER AGAIN)
expect(() => hashPassword('short')).toThrow(); // 12 character minimum

// Attack: Password minimum changed to 16 in one file but not others = inconsistent security
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Single source of truth with centralized constants and validation
import { z } from 'zod';

// ✅ Centralized constants (single place to update)
export const AUTH_CONSTANTS = {
  MIN_PASSWORD_LENGTH: 12,
  MAX_PASSWORD_LENGTH: 128,
  PASSWORD_REGEX: /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/,
  MIN_EMAIL_LENGTH: 5,
  MAX_EMAIL_LENGTH: 255
} as const;

// ✅ Reusable validation schemas (DRY for validation logic)
export const emailSchema = z.string()
  .trim()
  .min(AUTH_CONSTANTS.MIN_EMAIL_LENGTH)
  .max(AUTH_CONSTANTS.MAX_EMAIL_LENGTH)
  .email('Invalid email format');

export const passwordSchema = z.string()
  .min(AUTH_CONSTANTS.MIN_PASSWORD_LENGTH,
    `Password must be at least ${AUTH_CONSTANTS.MIN_PASSWORD_LENGTH} characters`)
  .max(AUTH_CONSTANTS.MAX_PASSWORD_LENGTH)
  .regex(AUTH_CONSTANTS.PASSWORD_REGEX,
    'Password must contain uppercase, number, and special character');

export const userInputSchema = z.object({
  email: emailSchema,
  password: passwordSchema
});

// ✅ Extracted validation function (used everywhere)
export function validateUserInput(input: unknown): { email: string; password: string } {
  return userInputSchema.parse(input);
}

// ✅ Higher-order function for error handling (no repeated try/catch)
export function withErrorHandling<T>(
  fn: () => Promise<T>
): Promise<T> {
  return fn().catch(error => {
    logger.error('Error:', error);
    throw new Error('Operation failed');
  });
}

// ✅ Routes use centralized validation (no duplication)
app.post('/users', async (req, res) => {
  const validated = validateUserInput(req.body); // Single validation function
  const user = await withErrorHandling(() => createUser(validated));
  res.json(user);
});

app.post('/login', async (req, res) => {
  const validated = validateUserInput(req.body); // Same validation function
  const token = await withErrorHandling(() => authenticate(validated));
  res.json({ token });
});

// ✅ Tests use same constants
describe('Password validation', () => {
  it('rejects passwords shorter than minimum', () => {
    const short = 'a'.repeat(AUTH_CONSTANTS.MIN_PASSWORD_LENGTH - 1);
    expect(() => passwordSchema.parse(short)).toThrow();
  });
});

// ✅ Key Patterns:
// 1. Centralized constants: All magic numbers in config/constants.ts with descriptive names
// 2. Reusable validation: Zod schemas used everywhere (routes, services, tests)
// 3. Extract function: Duplicated code blocks become single utility function
// 4. Higher-order functions: Cross-cutting concerns (logging, error handling) abstracted
// 5. Single source of truth: Changes in one place propagate to all consumers automatically
```

## Human Review Checklist

- [ ] **Code Duplication Metrics** — Code duplication <3% measured by jscpd or SonarQube, no blocks >6 lines duplicated >2 times (run duplication analysis, identify hotspots, extract to reusable functions)

- [ ] **Centralized Constants** — All magic numbers and strings extracted to config/constants.ts with descriptive names (grep for hardcoded values like /\b12\b/ or /"admin"/, verify referenced from central constants, test changing constant updates all usages)

- [ ] **Reusable Validation** — Validation rules centralized in Zod schemas, used consistently across routes/services/tests (verify no inline validation logic, ensure same schema used everywhere, test consistency)

- [ ] **Higher-Order Abstractions** — Repeated patterns (try/catch, logging, auth checks) extracted to middleware/decorators/HOFs (grep for repeated try/catch blocks, verify cross-cutting concerns abstracted, ensure composable)

- [ ] **No Divergent Implementations** — Similar functionality uses same implementation (grep for multiple implementations of same feature, verify security-critical code not duplicated, ensure single source of truth for auth/validation)

- [ ] **Test Consistency** — Tests reference same constants as production code, ensuring changes propagate (verify tests import from config/constants, ensure no hardcoded test values, validate test changes with constant updates)

---

**Key Takeaway**: Duplication is far cheaper than the wrong abstraction; apply the Rule of Three (wait until duplication appears 3 times before extracting) but always centralize security-critical logic immediately.
