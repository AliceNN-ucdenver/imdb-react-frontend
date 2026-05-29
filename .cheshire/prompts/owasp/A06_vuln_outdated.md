# Vulnerable and Outdated Components — Compact Remediation Guide

## What is Vulnerable Components?

Applications using components (libraries, frameworks, modules) with known vulnerabilities may undermine defenses and enable serious attacks when vulnerable components are exploited.

## STRIDE Mapping

- **Primary**: Tampering (compromised dependencies inject malicious code)
- **Secondary**: Elevation of Privilege (exploiting CVEs for system access), Information Disclosure (vulnerable libraries leak data)

## Types/Patterns of Vulnerable Components

- **Unpatched Dependencies**: Using npm packages with known CVEs listed in vulnerability databases
- **Outdated Versions**: Running old framework versions without security updates
- **No Integrity Verification**: Loading external scripts without Subresource Integrity (SRI) checks
- **Eval() with Remote Code**: Executing untrusted JavaScript from CDNs or APIs
- **Wildcard Version Ranges**: Using `^` or `~` allowing vulnerable minor/patch versions
- **Unused Dependencies**: Bloated dependency trees increasing attack surface

## What It Looks Like (TypeScript)

```typescript
// ❌ CRITICAL: eval() executes arbitrary remote code
export async function loadRemoteConfig(url: string) {
  const response = await fetch(url);
  const code = await response.text();
  eval(code); // ❌ EXTREMELY DANGEROUS!
}

// package.json with vulnerable dependencies
{
  "dependencies": {
    "express": "^3.21.2",  // ❌ Old version with known CVEs
    "lodash": "~4.17.15",  // ❌ Vulnerable to prototype pollution
    "mongoose": "*"        // ❌ Wildcard allows any version!
  }
}

// HTML loading script without integrity check
<script src="https://cdn.example.com/library.js"></script>
// ❌ No SRI - if CDN is compromised, malicious code executes!
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Safe resource loading with integrity verification
import crypto from 'crypto';

interface TrustedResource {
  url: string;
  integrity: string; // SHA-384 SRI hash
  type: 'json' | 'script';
}

// ✅ Allowlist with SRI hashes
const TRUSTED_RESOURCES: Record<string, TrustedResource> = {
  'app-config': {
    url: 'https://cdn.example.com/config.json',
    integrity: 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC',
    type: 'json'
  }
};

// ✅ Verify content integrity
function verifyIntegrity(content: string, expectedIntegrity: string): boolean {
  const [algorithm, expectedHash] = expectedIntegrity.split('-');

  const actualHash = crypto
    .createHash(algorithm as 'sha256' | 'sha384' | 'sha512')
    .update(content, 'utf8')
    .digest('base64');

  return crypto.timingSafeEqual(
    Buffer.from(actualHash),
    Buffer.from(expectedHash)
  );
}

// ✅ Load and verify trusted resource
export async function loadTrustedResource(resourceName: string): Promise<any> {
  const resource = TRUSTED_RESOURCES[resourceName];
  if (!resource) {
    throw new Error(`Resource '${resourceName}' not in trusted list`);
  }

  const response = await fetch(resource.url);
  const content = await response.text();

  // ✅ Verify integrity BEFORE using content
  if (!verifyIntegrity(content, resource.integrity)) {
    throw new Error(`Integrity verification failed for ${resourceName}`);
  }

  // ✅ Parse safely (never eval!)
  if (resource.type === 'json') {
    return JSON.parse(content);
  }

  return content;
}

// ✅ Secure package.json with pinned versions
{
  "dependencies": {
    "express": "4.18.2",        // ✅ Exact version pinned
    "helmet": "7.1.0",          // ✅ No ^ or ~
    "bcrypt": "5.1.1"
  },
  "scripts": {
    "audit": "npm audit --audit-level=moderate",
    "check-outdated": "npm outdated"
  }
}

// ✅ Secure HTML with SRI
<script
  src="https://cdn.jsdelivr.net/npm/vue@3.3.13/dist/vue.global.prod.js"
  integrity="sha384-qH4M5EkT4JsFVrzLIgzSQJQVcr0lWtN7P4lqLsPlgHYrqh7C6vKwMDLU7t3r0ZqN"
  crossorigin="anonymous"
></script>

// ✅ Key Patterns:
// 1. Exact version pinning (no ^ or ~) for reproducible builds
// 2. SRI hashes for all external scripts verify content integrity
// 3. JSON.parse() for data, never eval() which executes code
// 4. npm audit in CI/CD fails builds on high/critical vulnerabilities
// 5. Regular dependency updates (quarterly review, 3-month staleness rule)
```

## Human Review Checklist

- [ ] **Dependency Version Pinning** — All package versions pinned to exact versions without ^ or ~ prefixes, package-lock.json contains integrity hashes (test run npm install verify package-lock.json unchanged, no ^ or ~ in package.json)

- [ ] **Vulnerability Scanning** — npm audit run in project root, all high and critical vulnerabilities addressed, CI/CD fails builds if vulnerabilities above threshold (test run npm audit verify exit code 0, trigger build with vulnerable package verify failure)

- [ ] **Subresource Integrity** — Every external script and stylesheet has integrity attribute with SHA-384 or SHA-512 hash, crossorigin="anonymous" included (test modify one character of integrity hash, verify browser shows SRI error and script doesn't execute)

- [ ] **No Dynamic Code Execution** — No eval(), Function(), vm.runInContext() calls with user input or remote content, JSON data parsed with JSON.parse() (test search codebase with grep -r "eval(", verify no matches for Function(, all dynamic content uses safe methods)

- [ ] **Unused Dependencies Cleanup** — npx depcheck identifies unused packages, transitive dependencies reviewed with npm ls (test run npx depcheck verify "No depcheck issue", review npm ls for reasonable tree depth)

- [ ] **Supply Chain Security** — Package authenticity verified with npm view, package signatures checked with npm audit signatures, package-lock.json committed to git (test run npm audit signatures, check NPM package page for verification badge, review dependencies on GitHub)

---

**Key Takeaway**: Dependencies are code you didn't write but are responsible for securing - pin versions, scan for vulnerabilities, verify integrity with SRI, and never use eval() with remote content.
