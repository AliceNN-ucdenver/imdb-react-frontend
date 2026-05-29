# Technical Debt Management — Compact Remediation Guide

## What is Technical Debt Management?

Technical Debt Management is the systematic tracking, prioritization, and paydown of accumulated code quality issues through structured debt registers (YAML/JSON), automated detection, and the 20% rule (allocate 20% of sprint capacity to debt paydown).

## Related OWASP

- **Primary**: A04 - Insecure Design (complexity debt increases attack surface and makes security audits difficult)
- **Secondary**: A06 - Vulnerable and Outdated Components (dependency debt tracked as P0 security issues)

## Types/Patterns of Technical Debt

- **Security Debt**: Hardcoded secrets, weak encryption, injection vulnerabilities (P0: <7 day SLA)
- **Maintainability Debt**: High complexity (>10), duplicate code, missing tests (P2: <90 days)
- **Performance Debt**: N+1 queries, memory leaks, inefficient algorithms (P1 if user-facing)
- **Dependency Debt**: Packages >90 days old, known CVEs, deprecated libraries (P0 if security)
- **Documentation Debt**: Missing API docs, outdated README, no architecture diagrams (P3: best effort)
- **Test Debt**: Coverage <80%, flaky tests, missing integration tests (P2: <90 days)

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Untracked debt accumulates invisibly
// Complex function ships without measurement (complexity 18)
function processOrder(order, user, inventory) {
  if (order) { if (user) { if (user.active) { /* 18 nested conditions */ }}}
}

// TODO comments scattered without tracking
// TODO: Fix SQL injection vulnerability
// FIXME: This is slow, need to optimize
// HACK: Temporary workaround for race condition

// Outdated dependencies with CVEs merge undetected
{
  "dependencies": {
    "lodash": "4.17.15"  // CVE-2020-8203, >2 years old
  }
}

// No structured tracking = invisible debt
// PR reviewer: "Looks good, merge it!"
// 6 months later: Codebase unmaintainable, features take weeks not days

// Attack: SQL injection TODO ignored for months, exploited in production
// Attack: CVE in lodash used for RCE because dependency too old to update safely
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Structured debt tracking with automated detection and enforcement

// ✅ TECHNICAL-DEBT.yml (single source of truth)
/*
- id: DEBT-001
  title: processOrder function has complexity 18
  category: maintainability
  severity: P1
  effort: M (4-8h)
  impact: H (blocks feature development)
  file: src/services/orders.ts:42
  created: 2024-10-01
  assignee: dev@example.com
  notes: |
    Refactor using Extract Method and Strategy Pattern.
    Target complexity ≤8. See complexity-reduction.md prompt pack.

- id: DEBT-002
  title: lodash 4.17.15 has CVE-2020-8203
  category: security
  severity: P0
  effort: S (<4h)
  impact: H (RCE vulnerability)
  file: package.json:12
  created: 2024-10-05
  assignee: security-team@example.com
  notes: |
    Upgrade to lodash 4.17.21. Run npm audit after.
    SLA: Must fix within 7 days (P0 security).
*/

// ✅ scripts/detect-debt.ts - Automated debt detection
import { execSync } from 'child_process';
import { writeFileSync, readFileSync } from 'fs';
import { parse, stringify } from 'yaml';

interface DebtItem {
  id: string;
  title: string;
  category: 'security' | 'performance' | 'maintainability' | 'testing' | 'documentation';
  severity: 'P0' | 'P1' | 'P2' | 'P3';
  effort: 'S' | 'M' | 'L' | 'XL';
  impact: 'H' | 'M' | 'L';
  file: string;
  created: string;
  assignee: string | null;
  notes: string;
}

export async function detectDebt(): Promise<void> {
  const existingDebt: DebtItem[] = parse(
    readFileSync('TECHNICAL-DEBT.yml', 'utf-8')
  );

  const newDebt: DebtItem[] = [];

  // ✅ Detect TODO/FIXME comments
  const todos = execSync('grep -r "TODO:\\|FIXME:" src/', { encoding: 'utf-8' })
    .split('\n')
    .filter(Boolean);

  for (const todo of todos) {
    const [file, comment] = todo.split(':');
    const exists = existingDebt.some(d => d.file === file && d.title.includes(comment.slice(0, 50)));

    if (!exists) {
      newDebt.push({
        id: getNextDebtId(existingDebt),
        title: comment.trim(),
        category: 'maintainability',
        severity: 'P2',
        effort: 'M',
        impact: 'M',
        file,
        created: new Date().toISOString().split('T')[0],
        assignee: null,
        notes: 'Auto-detected TODO comment. Assign owner and estimate effort.'
      });
    }
  }

  // ✅ Detect high complexity functions
  const complexity = execSync('npx ts-complex src/', { encoding: 'utf-8' });
  const violations = complexity
    .split('\n')
    .filter(line => line.match(/complexity: ([0-9]+)/) && parseInt(line.match(/complexity: ([0-9]+)/)[1]) > 10);

  for (const violation of violations) {
    const match = violation.match(/^(.+?):(\d+).+complexity: (\d+)/);
    if (match) {
      const [, file, line, comp] = match;
      const exists = existingDebt.some(d => d.file === `${file}:${line}`);

      if (!exists) {
        newDebt.push({
          id: getNextDebtId([...existingDebt, ...newDebt]),
          title: `Function has complexity ${comp} (threshold: 10)`,
          category: 'maintainability',
          severity: parseInt(comp) > 15 ? 'P1' : 'P2',
          effort: 'M',
          impact: 'H',
          file: `${file}:${line}`,
          created: new Date().toISOString().split('T')[0],
          assignee: null,
          notes: 'Refactor using Extract Method, Guard Clauses, or Strategy Pattern.'
        });
      }
    }
  }

  // ✅ Detect outdated dependencies
  const outdated = JSON.parse(
    execSync('npm outdated --json', { encoding: 'utf-8' }) || '{}'
  );

  for (const [name, info] of Object.entries(outdated)) {
    const ageDays = await getDependencyAge(name, info.current);
    if (ageDays > 90) {
      const exists = existingDebt.some(d => d.title.includes(name));

      if (!exists) {
        newDebt.push({
          id: getNextDebtId([...existingDebt, ...newDebt]),
          title: `${name}@${info.current} is ${ageDays} days old`,
          category: 'dependency',
          severity: 'P1',
          effort: 'S',
          impact: 'M',
          file: 'package.json',
          created: new Date().toISOString().split('T')[0],
          assignee: null,
          notes: `Upgrade to ${info.latest}. Check for breaking changes.`
        });
      }
    }
  }

  // ✅ Write updated debt register
  if (newDebt.length > 0) {
    const allDebt = [...existingDebt, ...newDebt];
    writeFileSync('TECHNICAL-DEBT.yml', stringify(allDebt));
    console.log(`✅ Added ${newDebt.length} new debt items (${allDebt.length} total)`);
  }

  // ✅ Fail CI if P0 debt detected
  const p0Debt = [...existingDebt, ...newDebt].filter(d => d.severity === 'P0');
  if (p0Debt.length > 0) {
    console.error(`❌ ${p0Debt.length} P0 (critical) debt items must be fixed within 7 days`);
    p0Debt.forEach(d => console.error(`  ${d.id}: ${d.title} (${d.file})`));
    process.exit(1);
  }
}

function getNextDebtId(existing: DebtItem[]): string {
  const maxId = existing.reduce((max, d) => {
    const num = parseInt(d.id.replace('DEBT-', ''));
    return num > max ? num : max;
  }, 0);
  return `DEBT-${String(maxId + 1).padStart(3, '0')}`;
}

// ✅ .github/workflows/debt-prevention.yml
/*
name: Debt Prevention
on: [pull_request]
jobs:
  prevent-untracked-debt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: ts-node scripts/detect-debt.ts
      - run: |
          if git diff --quiet TECHNICAL-DEBT.yml; then
            echo "✅ No new debt detected"
          else
            echo "⚠️ This PR adds new debt items:"
            git diff TECHNICAL-DEBT.yml
            # Comment on PR with new debt items
          fi
*/

// ✅ Key Patterns:
// 1. Structured tracking: YAML register with id/category/severity/effort/impact schema
// 2. Automated detection: Scripts scan for TODO, complexity, outdated deps, CVEs
// 3. Unique IDs: DEBT-XXX auto-incrementing, never reused (prevents confusion)
// 4. SLA enforcement: P0 <7d, P1 <30d, P2 <90d with CI failures for violations
// 5. 20% rule: Team allocates 20% sprint capacity to debt paydown (not 0%, not 100%)
```

## Human Review Checklist

- [ ] **Debt Register Schema** — TECHNICAL-DEBT.yml follows strict schema with id/title/category/severity/effort/impact/file/created/assignee/notes (verify all fields present, test YAML parses correctly, ensure file paths include line numbers)

- [ ] **Automated Detection** — Script scans for TODO/FIXME comments, complexity >10, dependencies >90 days old (verify uses ts-complex not manual AST, test detects known issues, ensure deduplication works correctly)

- [ ] **ID Generation** — Debt IDs auto-increment (DEBT-001, DEBT-002) with leading zeros, never reused (verify script reads max ID and increments, test no duplicates created, ensure transaction-like approach)

- [ ] **SLA Tracking** — Each debt item has creation date, SLAs defined (P0: <7 days, P1: <30 days, P2: <90 days), report flags overdue items (verify age calculated correctly, test SLA violations detected, ensure escalation process documented)

- [ ] **CI Enforcement** — Workflow fails if new TODO comments without debt ticket, or complexity increased >5% without refactoring plan (verify blocks PR merge, test error messages actionable, ensure comments on PR with summary)

- [ ] **20% Rule Adherence** — Team allocates 20% sprint capacity to debt paydown, velocity tracked (verify sprint retrospectives include debt work, test debt closed per sprint measured, ensure not constantly deprioritized)

---

**Key Takeaway**: Technical debt isn't inherently bad—it's a trade-off for speed; the problem is invisible, untracked debt that compounds until refactoring becomes impossible and security vulnerabilities accumulate unnoticed.
