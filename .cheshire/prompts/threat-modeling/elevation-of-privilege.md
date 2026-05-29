# Elevation of Privilege — Compact Remediation Guide

## What is Elevation of Privilege?

Elevation of Privilege occurs when attackers gain unauthorized permissions beyond their authorized level through missing authorization checks, RBAC bypass, parameter manipulation, or exploiting insecure direct object references.

## Related OWASP

- **Primary**: A01 - Broken Access Control
- **Secondary**: A04 - Insecure Design (missing authorization architecture)

## Types of Elevation of Privilege

- **Missing Authorization**: Endpoints that don't verify user permissions before privileged operations
- **RBAC Bypass**: Manipulating role assignments or bypassing role validation checks
- **Parameter Tampering**: Changing user IDs or role fields in API requests
- **IDOR**: Accessing admin resources by guessing or enumerating resource IDs
- **Path Traversal**: Using `../` to escape restricted directories and access configuration files

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: JWT role claim trusted without server-side validation
const authorize = (allowedRoles) => (req, res, next) => {
  const { role } = req.user; // From decoded JWT

  if (!allowedRoles.includes(role)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  next();
};

app.delete("/api/admin/users/:id",
  isAuthenticated,
  authorize(["admin"]), // Only checks JWT claim!
  async (req, res) => {
    await db.query("DELETE FROM users WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  }
);
// Attack: Attacker modifies JWT payload {"role": "admin"}, signs with weak secret

// ❌ VULNERABLE: Mass assignment allowing role modification
app.put("/api/users/:userId", isAuthenticated, async (req, res) => {
  const userId = req.params.userId;

  if (req.user.id !== userId) {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Accepts ALL fields from request body including role!
  await db.query(
    "UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4",
    [req.body.name, req.body.email, req.body.role, userId]
  );

  res.json({ success: true });
});
// Attack: User adds {"role": "admin"} to profile update request

// ❌ VULNERABLE: Path traversal to access admin config files
app.get("/api/files/:filename", isAuthenticated, async (req, res) => {
  const filePath = join("/uploads", req.params.filename);
  const data = await readFile(filePath);
  res.send(data);
});
// Attack: GET /api/files/../../config/database.yml leaks credentials
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Multi-layer privilege enforcement
import { z } from "zod";
import { join, resolve, basename } from "path";

// ✅ Key Pattern 1: Always fetch role from authoritative source
const authorize = (allowedRoles) => async (req, res, next) => {
  // Fetch current user role from database (never trust JWT claims)
  const user = await db.query(
    "SELECT role FROM users WHERE id = $1",
    [req.user.id]
  );

  if (!user) {
    return res.status(401).json({ error: "User not found" });
  }

  if (!allowedRoles.includes(user.role)) {
    logger.warn({
      event: "authorization_failed",
      userId: req.user.id,
      requiredRoles: allowedRoles,
      actualRole: user.role,
      endpoint: req.path
    });

    return res.status(403).json({ error: "Forbidden" });
  }

  req.userRole = user.role;
  next();
};

app.delete("/api/admin/users/:id",
  isAuthenticated,
  authorize(["admin", "superadmin"]),
  async (req, res) => {
    const targetUserId = req.params.id;

    // Additional check: admins can't delete superadmins
    const targetUser = await db.query(
      "SELECT role FROM users WHERE id = $1",
      [targetUserId]
    );

    if (targetUser.role === "superadmin" && req.userRole !== "superadmin") {
      return res.status(403).json({
        error: "Cannot delete superadmin user"
      });
    }

    await db.query("DELETE FROM users WHERE id = $1", [targetUserId]);

    logger.info({
      event: "user_deleted",
      actorId: req.user.id,
      actorRole: req.userRole,
      targetId: targetUserId
    });

    res.json({ success: true });
  }
);

// ✅ Key Pattern 2: Explicit field allowlists per role
const userProfileSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  bio: z.string().max(500).optional()
});

const adminProfileSchema = userProfileSchema.extend({
  role: z.enum(["user", "moderator"]) // Admin can only promote to moderator
});

app.put("/api/users/:userId", isAuthenticated, async (req, res) => {
  const userId = parseInt(req.params.userId);

  // Fetch authoritative role
  const actor = await db.query(
    "SELECT role FROM users WHERE id = $1",
    [req.user.id]
  );

  // Authorization: user can only update their own profile
  if (req.user.id !== userId && actor.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Validate input based on actor's role
  const schema = actor.role === "admin" ? adminProfileSchema : userProfileSchema;

  let validatedData;
  try {
    validatedData = schema.parse(req.body);
  } catch (err) {
    return res.status(400).json({ error: err.errors });
  }

  // Build update query with only allowed fields
  const fields = Object.keys(validatedData);
  const values = Object.values(validatedData);
  const setClause = fields.map((f, i) => `${f} = $${i + 1}`).join(", ");

  await db.query(
    `UPDATE users SET ${setClause} WHERE id = $${fields.length + 1}`,
    [...values, userId]
  );

  logger.info({
    event: "profile_updated",
    actorId: req.user.id,
    targetUserId: userId,
    updatedFields: fields
  });

  res.json({ success: true });
});

// ✅ Key Pattern 3: Path validation preventing traversal
const UPLOAD_DIR = resolve("/var/app/uploads");

app.get("/api/files/:fileId", isAuthenticated, async (req, res) => {
  // Use database to map fileId to path (prevents traversal)
  const file = await db.query(
    "SELECT filename, owner_id, mime_type FROM files WHERE id = $1",
    [req.params.fileId]
  );

  if (!file) {
    return res.status(404).json({ error: "File not found" });
  }

  // Authorization: check ownership or admin
  const actor = await db.query(
    "SELECT role FROM users WHERE id = $1",
    [req.user.id]
  );

  if (file.owner_id !== req.user.id && actor.role !== "admin") {
    logger.warn({
      event: "unauthorized_file_access",
      userId: req.user.id,
      fileId: req.params.fileId,
      ownerId: file.owner_id
    });

    return res.status(403).json({ error: "Forbidden" });
  }

  // Sanitize filename (remove path separators)
  const safeFilename = basename(file.filename);

  // Validate path is within UPLOAD_DIR
  const filePath = resolve(join(UPLOAD_DIR, safeFilename));

  if (!filePath.startsWith(UPLOAD_DIR)) {
    logger.error({
      event: "path_traversal_attempt",
      userId: req.user.id,
      requestedFile: file.filename,
      resolvedPath: filePath
    });

    return res.status(400).json({ error: "Invalid file path" });
  }

  const data = await readFile(filePath);
  res.type(file.mime_type);
  res.send(data);
});

// ✅ Key Pattern 4: Deny-by-default authorization
// Default response is 403 Forbidden unless explicitly granted

// ✅ Key Pattern 5: Defense in depth - multiple authorization layers
// 1. Network level (firewall rules)
// 2. Application level (middleware checks)
// 3. Database level (row-level security policies)
```

## Human Review Checklist

- [ ] **Server-Side Authorization** — Every privileged operation checks authorization server-side, never relies on client-side checks (attempt admin actions while logged in as regular user, modify JWT claims and verify they're ignored, test authorization enforced even when bypassing UI)

- [ ] **Role-Based Access Control** — Clear role hierarchy implemented with database as single source of truth, users cannot modify their own role field (document all roles and permissions, verify role field has database constraints, test role changes require admin approval, check role validation fetches from database not JWT)

- [ ] **Mass Assignment Prevention** — Explicit field allowlists define which fields each role can modify, no SELECT * or UPDATE * (submit requests with extra fields like role:admin and verify rejection, test database updates only touch allowed columns, verify separate validation schemas for different roles)

- [ ] **Resource Ownership** — Ownership checks ensure users only access their own resources unless admin (log in as User A, attempt to access User B's resources by changing IDs, verify 403 Forbidden responses, check database queries include WHERE user_id = $1 filters)

- [ ] **Path Validation** — File paths use database-backed UUIDs, basename() strips directory components, absolute paths verified within allowed directories (test path traversal with ../, ..%2F, and URL-encoded variants, verify all attempts blocked and logged, check object storage used instead of file system where possible)

- [ ] **Least Privilege and Defense in Depth** — Users granted minimum permissions, multiple authorization layers at network/app/database levels (audit role permissions and remove unnecessary access, verify database users have minimal privileges, test MFA required for admin actions, check approval workflows for sensitive operations)

---

**Key Takeaway**: Elevation of Privilege is prevented by rigorous server-side authorization — never trust client-provided claims, always verify permissions against authoritative server-side data, default to deny.
