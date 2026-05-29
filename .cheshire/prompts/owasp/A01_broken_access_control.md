# Broken Access Control — Compact Remediation Guide

## What is Broken Access Control?

Access control failures occur when applications fail to properly enforce authorization checks, allowing users to access resources or perform actions beyond their intended permissions.

## STRIDE Mapping

- **Primary**: Elevation of Privilege (attackers gain unauthorized access)
- **Secondary**: Information Disclosure (unauthorized data access via IDOR)

## Types/Patterns of Broken Access Control

- **IDOR (Insecure Direct Object References)**: Changing URL parameter `id=123` to `id=456` grants access to another user's resource
- **Missing Authorization**: Authentication present but authorization checks absent on protected routes
- **Privilege Escalation**: Regular users accessing admin functions via direct URL manipulation
- **Metadata Manipulation**: Tampering with JWT claims, cookies, or hidden fields to elevate privileges
- **CORS Misconfiguration**: API accessible from unauthorized origins enabling cross-origin attacks

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: IDOR - no ownership check
export async function getUserDocument(userId: string, documentId: string) {
  const doc = await db.query('SELECT * FROM documents WHERE id = $1', [documentId]);
  return doc.rows[0];
  // Attack: Any authenticated user can access ANY document by changing documentId
}

// ❌ VULNERABLE: Missing role check
export async function deleteAllUsers(req: Request, res: Response) {
  await db.query('DELETE FROM users');
  res.json({ message: 'Users deleted' });
  // Attack: No role verification - any authenticated user can delete all users
}
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Proper authorization with ownership validation
import { Request, Response, NextFunction } from 'express';

interface AuthRequest extends Request {
  user?: { id: string; role: 'admin' | 'user' | 'guest' };
}

// ✅ Centralized role-based access control
export function requireRole(allowedRoles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      console.warn('Authorization failed', {
        userId: req.user.id,
        role: req.user.role,
        required: allowedRoles,
        path: req.path
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// ✅ Resource ownership validation
export async function getUserDocument(
  requesterId: string,
  documentId: string,
  requesterRole: string
) {
  const doc = await db.query('SELECT * FROM documents WHERE id = $1', [documentId]);
  if (!doc.rows[0]) throw new Error('Document not found');

  // ✅ Verify ownership OR admin access
  const isOwner = doc.rows[0].owner_id === requesterId;
  const isAdmin = requesterRole === 'admin';

  if (!isOwner && !isAdmin) {
    console.error('Access control violation', { requesterId, documentId });
    throw new Error('Access denied');
  }

  return doc.rows[0];
}

// ✅ Key Patterns:
// 1. Deny-by-default authorization - access must be explicitly granted
// 2. Never trust client-provided user IDs or roles from headers/cookies/body
// 3. Centralized middleware enforces role checks consistently across routes
// 4. Ownership validation checks user owns resource OR has admin role
// 5. All authorization failures logged with context for security monitoring
```

## Human Review Checklist

- [ ] **Authorization Middleware** — Deny-by-default approach where access must be explicitly granted, never trust client-provided data like user IDs or roles (test protected routes without authentication, with wrong role, verify 401/403 responses)

- [ ] **IDOR Protection** — Every function accessing user resources validates ownership before returning data, validation happens server-side (test as user A attempting to access user B's resources by ID manipulation, verify all fail with 403)

- [ ] **Role-Based Access Control** — Each protected route explicitly declares required roles using middleware, admin functions require explicit role checks not just authentication (create test users with each role, verify they only access appropriate endpoints)

- [ ] **Function-Level Access** — Administrative functions require explicit role checks, direct URL access to admin functions blocked for non-admin users (use curl/Postman to attempt direct API calls to admin endpoints with non-admin tokens, verify rejection)

- [ ] **Authorization Context** — User context (ID, role, permissions) comes from authenticated session or JWT only, never from request parameters/headers/body (attempt to forge authorization by adding custom headers or manipulating payloads, verify ignored)

- [ ] **Audit Logging** — All authorization failures logged with sufficient context including user ID, requested resource, required permission, IP, timestamp (trigger authorization failures, verify logs contain necessary details without sensitive data)

---

**Key Takeaway**: Authentication verifies identity; authorization verifies permission - implement both with deny-by-default policies and centralized middleware.
