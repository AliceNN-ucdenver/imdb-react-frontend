# Dependency Hygiene — Compact Remediation Guide

## What is Dependency Hygiene?

Dependency Hygiene is the practice of keeping all dependencies fresh (≤90 days old) through automated updates, security scanning, and exact version pinning to prevent security vulnerabilities and breaking changes from accumulating.

## Related OWASP

- **Primary**: A06 - Vulnerable and Outdated Components (outdated dependencies have known CVEs that attackers exploit)
- **Secondary**: A05 - Security Misconfiguration (using semver ranges like ^ allows untested versions into production)

## Types/Patterns of Dependency Debt

- **Outdated Dependencies**: Packages >90 days old accumulate security vulnerabilities and make upgrades increasingly risky
- **Semver Range Violations**: Using ^ or ~ in package.json allows untested minor/patch versions to break production
- **Known CVEs**: Dependencies with published vulnerabilities exploitable by attackers
- **Unmaintained Packages**: Libraries with no updates in >2 years indicate abandonment
- **Transitive Dependencies**: Vulnerable packages deep in dependency tree often overlooked
- **Major Version Lag**: Being >2 major versions behind makes migration exponentially harder

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: package.json with security issues
{
  "dependencies": {
    "express": "^4.17.1",        // ^ allows ANY 4.x version (untested)
    "lodash": "4.17.15",          // Pinned but has CVE-2020-8203
    "moment": "2.29.1",           // Deprecated, published 2+ years ago
    "axios": "~0.21.0"            // Known CVE-2021-3749
  }
  // Missing: "engines" field (Node version not locked)
  // Missing: "packageManager" field (npm version not locked)
}

// Attack: npm install pulls untested 4.18.x version of express with breaking changes
// Attack: CVE-2020-8203 in lodash allows prototype pollution leading to RCE
// Attack: Transitive dependency vulnerability exploited through axios
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: package.json with exact versions and security controls
{
  "engines": {
    "node": "18.x",
    "npm": "9.x"
  },
  "packageManager": "npm@9.8.1",
  "dependencies": {
    "express": "4.18.2",         // Exact version, no ^ or ~
    "zod": "3.22.4",              // Modern alternative to lodash
    "date-fns": "2.30.0",         // Maintained alternative to moment
    "axios": "1.6.0"              // Latest with CVE fixes
  },
  "devDependencies": {
    "snyk": "1.1200.0",
    "npm-check-updates": "16.14.6"
  },
  "scripts": {
    "audit": "npm audit --audit-level=high && snyk test --severity-threshold=high",
    "check-freshness": "ts-node scripts/check-dependency-freshness.ts",
    "upgrade": "ncu -u && npm install && npm test"
  }
}

// ✅ scripts/check-dependency-freshness.ts
import { execSync } from 'child_process';

interface DependencyAge {
  name: string;
  version: string;
  publishedDays: number;
}

// ✅ Check dependency publish dates
export async function checkDependencyFreshness(maxAgeDays = 90): Promise<void> {
  const outdated = execSync('npm outdated --json', { encoding: 'utf-8' });
  const packages = JSON.parse(outdated || '{}');

  const violations: DependencyAge[] = [];

  for (const [name, info] of Object.entries(packages)) {
    const publishDate = execSync(
      `npm view ${name}@${info.current} time.modified`,
      { encoding: 'utf-8' }
    ).trim();

    const ageDays = Math.floor(
      (Date.now() - new Date(publishDate).getTime()) / (1000 * 60 * 60 * 24)
    );

    if (ageDays > maxAgeDays) {
      violations.push({ name, version: info.current, publishedDays: ageDays });
    }
  }

  if (violations.length > 0) {
    console.error(`❌ ${violations.length} dependencies exceed ${maxAgeDays} day threshold:`);
    violations.forEach(v => {
      console.error(`  ${v.name}@${v.version} (${v.publishedDays} days old)`);
    });
    process.exit(1);
  }

  console.log(`✅ All dependencies ≤${maxAgeDays} days old`);
}

// ✅ .github/renovate.json for automated updates
{
  "extends": ["config:base"],
  "schedule": ["every weekend"],
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "labels": ["dependencies", "auto-merge"]
    },
    {
      "matchUpdateTypes": ["minor"],
      "labels": ["dependencies", "review-required"]
    },
    {
      "matchUpdateTypes": ["major"],
      "labels": ["dependencies", "breaking-change"]
    }
  ],
  "vulnerabilityAlerts": {
    "labels": ["security"],
    "assignees": ["security-team"]
  }
}

// ✅ Key Patterns:
// 1. Exact version pinning: No ^ or ~ symbols prevent surprise breaking changes
// 2. Automated scanning: npm audit + Snyk on every PR catches CVEs before merge
// 3. Freshness enforcement: Fitness function fails CI if dependencies >90 days old
// 4. Automated updates: Renovate creates weekly PRs for patches with auto-merge
// 5. Engine locking: Node and npm versions specified to ensure deterministic builds
```

## Human Review Checklist

- [ ] **Exact Version Pinning** — All dependencies use exact versions with no ^ or ~ semver ranges (grep package.json for "\\^" or "~", verify engines and packageManager fields exist, test npm ci honors lockfile exactly)

- [ ] **Security Scanning** — CI runs npm audit and Snyk on every PR, fails on high/critical vulnerabilities (validate both tools configured with --audit-level=high and --severity-threshold=high, verify no continue-on-error bypasses, test catches known CVEs)

- [ ] **Freshness Enforcement** — Fitness function checks dependency publish dates and fails if >90 days old (verify script queries actual npm registry publish times, test fails for outdated packages, ensure threshold configurable via MAX_DEP_AGE_DAYS)

- [ ] **Automated Updates** — Renovate or Dependabot configured for weekly updates with auto-merge for patches (validate schedule runs on weekends, verify patch updates auto-merge if tests pass, ensure major updates require manual review)

- [ ] **Dependency Lockfiles** — package-lock.json committed to Git and used in CI with npm ci (grep .gitignore for package-lock.json, verify not ignored, ensure CI uses npm ci not npm install)

- [ ] **Upgrade Workflow** — Team allocates 20% sprint capacity to dependency updates, SLAs defined (P0 security: <7 days, P1 major versions: <30 days, P2 minor/patch: <90 days), validate exceptions documented

---

**Key Takeaway**: The 3-month freshness rule prevents dependency upgrades from becoming scary "big bang" migrations; small, frequent updates with automated scanning are safer than large, infrequent ones.
