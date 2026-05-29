# Injection — Compact Remediation Guide

## What is Injection?

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands or access unauthorized data.

## STRIDE Mapping

- **Primary**: Tampering (attackers inject malicious data to modify commands)
- **Secondary**: Information Disclosure (SQL injection exposes database contents), Elevation of Privilege (command injection gains system access)

## Types/Patterns of Injection

- **SQL Injection**: Malicious SQL in user input modifies database queries (`' OR '1'='1`)
- **NoSQL Injection**: JSON/JavaScript injection in MongoDB queries (`{$ne: null}`)
- **OS Command Injection**: Shell commands injected through user input (`;rm -rf /`)
- **LDAP Injection**: Manipulating LDAP filters to bypass authentication
- **Template Injection**: User input interpreted as template code in rendering engines
- **Header Injection**: CRLF injection in HTTP headers enabling response splitting

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: String concatenation creates SQL injection
const sql = `SELECT * FROM users WHERE email LIKE '%${emailQuery}%'`;
const result = await client.query(sql);
// Attack: emailQuery = "' OR '1'='1" returns all users

// ❌ VULNERABLE: NoSQL injection
const user = await db.collection('users').findOne(filter);
// Attack: filter = {$ne: null} bypasses authentication
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Parameterized queries with input validation
import { Client } from 'pg';
import { z } from 'zod';

// ✅ Zod schema for input validation
const searchQuerySchema = z.string()
  .trim()
  .max(100)
  .regex(/^[a-zA-Z0-9 _.\-@]*$/, 'Invalid characters');

export async function searchUsers(emailQuery: string): Promise<User[]> {
  // ✅ Validate input first
  const validatedQuery = searchQuerySchema.parse(emailQuery);

  const client = new Client({ /* config from env vars */ });
  await client.connect();

  try {
    // ✅ Parameterized query - SQL structure separate from data
    const sql = 'SELECT id, email, name FROM users WHERE email ILIKE $1';
    const result = await client.query<User>(sql, [`%${validatedQuery}%`]);
    return result.rows;
  } catch (err) {
    // ✅ Generic error (don't expose SQL details)
    console.error('Database error:', err);
    throw new Error('Search failed');
  } finally {
    await client.end();
  }
}

// ✅ Key Patterns:
// 1. Parameterized queries with $1, $2 placeholders - never concatenate user input into SQL
// 2. Input validation with Zod allowlist regex defining permitted characters
// 3. Length limits enforced (max 100 characters) to prevent abuse
// 4. Generic error messages prevent information leakage about schema
// 5. Environment variables for database credentials, never hardcoded
```

## Human Review Checklist

- [ ] **Parameterized Queries** — All database queries use placeholders ($1, $2, $3 or ?), never string concatenation (validate each query uses parameters array, grep for template literals containing SQL keywords)

- [ ] **Input Validation** — All user input passes through Zod schema validation with allowlist regex before use in queries (verify length limits enforced, test rejection of special characters like ', --, ;)

- [ ] **No String Concatenation** — SQL structure never built dynamically by appending user input (grep for patterns like `"SELECT" + userInput` or `` `INSERT INTO ${table}` ``, verify none exist)

- [ ] **Safe APIs & Output Encoding** — Never use eval(), Function(), or vm.runInContext() with user input; for shell commands use spawn() with argument arrays not exec() with concatenation (test file operations reject path traversal like ../../etc/passwd)

- [ ] **Error Handling** — Error messages to users are generic ("Search failed"), never expose SQL syntax, table names, or column names (verify production errors show only safe messages, detailed errors logged server-side only)

- [ ] **Defense in Depth** — Multiple layers: parameterization + input validation + least privilege database accounts (verify removing one layer doesn't expose vulnerability, test with SQL injection payloads)

---

**Key Takeaway**: Always separate code from data using parameterized queries and input validation with allowlist regex patterns.
