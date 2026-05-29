# Fitness Functions — Compact Remediation Guide

## What are Fitness Functions?

Fitness Functions are automated, objective quality gates that continuously validate architectural characteristics (complexity, coverage, performance, dependency freshness, security) and fail CI/CD builds when code degrades beyond acceptable thresholds.

## Related OWASP

- **Primary**: A06 - Vulnerable and Outdated Components (dependency freshness fitness function prevents known CVEs)
- **Secondary**: A04 - Insecure Design (complexity fitness function reduces attack surface by enforcing simple, auditable code)

## Types/Patterns of Fitness Functions

- **Cyclomatic Complexity**: Measures decision points per function (threshold: ≤10); high complexity correlates with defects
- **Test Coverage**: Measures line/branch/statement coverage (threshold: ≥80%); prevents untested code from shipping
- **Dependency Freshness**: Measures dependency age (threshold: ≤90 days); prevents security vulnerabilities from accumulating
- **Performance Regression**: Measures p95/p99 latency against baseline (threshold: <10% regression); catches performance degradation
- **Security Compliance**: Measures high/critical vulnerabilities (threshold: 0); blocks merges with known CVEs
- **Architecture Rules**: Measures layer violations (routes call services not DB directly); enforces clean architecture

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: No automated quality gates, manual reviews miss violations
// Complex function ships (complexity 18) because PR reviewer didn't measure
function processOrder(order, user, inventory, payment) {
  if (order) {
    if (user) {
      if (user.active) {
        if (inventory.has(order.item)) {
          if (payment.method === 'card') {
            // 18 nested conditions, no enforcement
          }
        }
      }
    }
  }
}

// Outdated dependencies with CVEs merge because no automated scanning
{
  "dependencies": {
    "lodash": "4.17.15"  // CVE-2020-8203, merged without detection
  }
}

// Performance regression ships (p95: 450ms, was 200ms) due to lack of monitoring
app.get('/api/orders', async (req, res) => {
  const orders = await db.query('SELECT * FROM orders'); // N+1 query
  // No performance baseline comparison before merge
});

// Attack: Complex code hides security flaw, CVE exploited, slow endpoint causes DoS
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Automated fitness functions enforce quality thresholds in CI
import { execSync } from 'child_process';
import { readFileSync } from 'fs';

// ✅ Fitness function: Cyclomatic complexity
export async function checkComplexity(maxComplexity = 10): Promise<void> {
  const result = execSync('npx ts-complex src/', { encoding: 'utf-8' });
  const violations = result
    .split('\n')
    .filter(line => {
      const match = line.match(/complexity: (\d+)/);
      return match && parseInt(match[1]) > maxComplexity;
    });

  if (violations.length > 0) {
    console.error(`❌ ${violations.length} functions exceed complexity ${maxComplexity}:`);
    violations.forEach(v => console.error(`  ${v}`));
    process.exit(1);
  }
}

// ✅ Fitness function: Test coverage
export async function checkCoverage(minCoverage = 80): Promise<void> {
  const coverage = JSON.parse(
    readFileSync('coverage/coverage-summary.json', 'utf-8')
  );

  const metrics = ['lines', 'branches', 'functions', 'statements'];
  const violations = metrics.filter(m => coverage.total[m].pct < minCoverage);

  if (violations.length > 0) {
    console.error(`❌ Coverage below ${minCoverage}%:`);
    violations.forEach(m => {
      console.error(`  ${m}: ${coverage.total[m].pct}%`);
    });
    process.exit(1);
  }
}

// ✅ Fitness function: Dependency freshness
export async function checkDependencyFreshness(maxAgeDays = 90): Promise<void> {
  const outdated = JSON.parse(
    execSync('npm outdated --json', { encoding: 'utf-8' }) || '{}'
  );

  const violations = [];
  for (const [name, info] of Object.entries(outdated)) {
    const publishDate = execSync(
      `npm view ${name}@${info.current} time.modified`,
      { encoding: 'utf-8' }
    ).trim();

    const ageDays = Math.floor(
      (Date.now() - new Date(publishDate).getTime()) / (1000 * 60 * 60 * 24)
    );

    if (ageDays > maxAgeDays) {
      violations.push({ name, version: info.current, days: ageDays });
    }
  }

  if (violations.length > 0) {
    console.error(`❌ ${violations.length} dependencies older than ${maxAgeDays} days`);
    violations.forEach(v => console.error(`  ${v.name}@${v.version} (${v.days}d)`));
    process.exit(1);
  }
}

// ✅ Fitness function: Performance regression
export async function checkPerformance(maxRegressionPct = 10): Promise<void> {
  const baseline = JSON.parse(readFileSync('baseline/perf-baseline.json', 'utf-8'));
  const current = await runLoadTest(); // autocannon or similar

  const p95Regression =
    ((current.latency.p95 - baseline.latency.p95) / baseline.latency.p95) * 100;

  if (p95Regression > maxRegressionPct) {
    console.error(`❌ Performance regression: p95 ${p95Regression.toFixed(1)}% slower`);
    console.error(`  Baseline: ${baseline.latency.p95}ms, Current: ${current.latency.p95}ms`);
    process.exit(1);
  }
}

// ✅ .github/workflows/fitness-functions.yml
/*
name: Fitness Functions
on: [pull_request, push]
jobs:
  quality-gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm test -- --coverage
      - run: ts-node tests/fitness-functions/complexity.test.ts
      - run: ts-node tests/fitness-functions/coverage.test.ts
      - run: ts-node tests/fitness-functions/dependency-freshness.test.ts
      - run: npm audit --audit-level=high
      - run: npx snyk test --severity-threshold=high
*/

// ✅ Key Patterns:
// 1. Executable tests: Fitness functions are Jest tests that measure and assert thresholds
// 2. Fail-fast: CI fails immediately if any fitness function threshold violated
// 3. Actionable errors: Error messages show actual vs expected values with remediation guidance
// 4. Baseline tracking: Historical metrics stored in baseline/ for regression detection
// 5. Configurable thresholds: Environment variables (MAX_COMPLEXITY, MIN_COVERAGE) enable tuning
```

## Human Review Checklist

- [ ] **Complexity Enforcement** — Fitness function uses ts-complex or SonarQube to measure cyclomatic complexity, fails if any function >10 (verify tool runs in CI, test with intentionally complex function, ensure actionable error messages with file:line locations)

- [ ] **Coverage Validation** — Fitness function reads Jest coverage report and validates all metrics ≥80% (verify coverage/coverage-summary.json parsed correctly, test fails if coverage drops, ensure baseline comparison detects regressions >2%)

- [ ] **Dependency Freshness** — Fitness function checks actual npm publish dates and fails if any dependency >90 days old (verify queries npm registry API, test with outdated package, ensure categorizes by severity: security vs minor updates)

- [ ] **Performance Testing** — Fitness function runs load tests against test server, measures p95/p99 latency, fails if >10% regression from baseline (verify server starts/stops cleanly, test detects latency increases, ensure baseline updated after intentional optimizations)

- [ ] **CI Integration** — GitHub Actions workflow runs all fitness functions on every PR with continue-on-error: false (verify workflow syntax valid, test triggers on pull_request event, ensure failure blocks merge, validate artifacts uploaded for trend analysis)

- [ ] **Baseline Management** — Baseline files (coverage-baseline.json, perf-baseline.json) committed to Git with metadata (timestamp, commit SHA), documentation explains update process (verify baselines realistic for current codebase, ensure regeneration procedure documented, test baseline updates propagate correctly)

---

**Key Takeaway**: Fitness functions prevent architectural erosion by making quality gates objective and automated; manual code reviews catch bugs, but fitness functions enforce standards at scale across the entire codebase.
