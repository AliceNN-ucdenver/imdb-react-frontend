# Strangler Fig Pattern — Compact Remediation Guide

## What is the Strangler Fig Pattern?

The Strangler Fig Pattern is an incremental migration strategy that gradually replaces a legacy system with new architecture by routing traffic through a proxy layer, allowing both systems to coexist during migration with instant rollback capability and zero downtime.

## Related OWASP

- **Primary**: A04 - Insecure Design (enables gradual migration from insecure legacy architecture to secure modern design)
- **Secondary**: A05 - Security Misconfiguration (feature flags prevent accidental exposure of new system before ready)

## Types/Patterns of Strangler Migrations

- **Shadow Mode**: New system processes requests but doesn't serve responses; used to validate behavior before cutover
- **Canary Release**: New system serves 5% → 25% → 50% → 100% of traffic with automatic rollback on errors
- **Dual Writes**: Both old and new databases updated during transition to maintain consistency
- **Feature Toggle**: Per-endpoint or per-user routing based on feature flags
- **Parallel Run**: Both systems process same requests, responses compared for validation
- **Backfill Migration**: Historical data migrated from old to new database incrementally

## What It Looks Like (TypeScript)

```typescript
// ❌ VULNERABLE: Big bang rewrite with no rollback capability
// Old monolith serving all traffic
app.get('/api/users/:id', async (req, res) => {
  const user = await oldDatabase.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(user);
});

// Team rewrites entire system for 18 months in separate branch
// Deploy day: flip switch, entire new system goes live at once
// If issues found: no rollback, system down for hours/days
// Risk: 80% of big bang rewrites fail catastrophically

// Attack: New system has security flaw missed in testing, entire user base exposed
// Attack: Performance regression not caught, all endpoints slow, no way to revert
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Strangler proxy with feature flags and gradual rollout
import { LaunchDarkly } from 'launchdarkly-node-server-sdk';

// ✅ Feature flag client for routing decisions
export class FeatureFlagClient {
  private client: LaunchDarkly.LDClient;

  async isEnabled(flag: string, userId?: string): Promise<boolean> {
    const user = userId ? { key: userId } : { key: 'anonymous' };
    return this.client.variation(flag, user, false); // Default: old system
  }

  async getCanaryPercentage(flag: string): Promise<number> {
    return this.client.variation(`${flag}-percentage`, { key: 'system' }, 0);
  }
}

// ✅ Strangler proxy routes traffic based on flags
export class StranglerRouter {
  constructor(
    private flags: FeatureFlagClient,
    private oldSystem: OldUserService,
    private newSystem: NewUserService
  ) {}

  async routeRequest(req: Request, res: Response): Promise<void> {
    const mode = await this.getRoutingMode(req.params.id);

    try {
      switch (mode) {
        case 'shadow':
          return await this.shadowMode(req, res);
        case 'canary':
          return await this.canaryMode(req, res);
        case 'full':
          return await this.newSystem.getUser(req.params.id);
        default:
          return await this.oldSystem.getUser(req.params.id);
      }
    } catch (err) {
      // ✅ Automatic fallback to old system on errors
      logger.error('New system error, falling back:', err);
      return await this.oldSystem.getUser(req.params.id);
    }
  }

  private async shadowMode(req: Request, res: Response): Promise<void> {
    // ✅ Run both systems, compare responses, return old response
    const [oldResult, newResult] = await Promise.all([
      this.oldSystem.getUser(req.params.id),
      this.newSystem.getUser(req.params.id).catch(err => ({ error: err.message }))
    ]);

    // ✅ Log differences for validation (non-blocking)
    this.compareResponses(oldResult, newResult, req.params.id);

    return oldResult; // Always return old system response in shadow mode
  }

  private async canaryMode(req: Request, res: Response): Promise<void> {
    const percentage = await this.flags.getCanaryPercentage('users-v2');
    const userId = req.params.id;

    // ✅ Consistent hashing: same user always gets same version
    const hash = parseInt(userId.slice(-8), 16);
    const bucket = hash % 100;

    if (bucket < percentage) {
      // Route to new system
      return await this.newSystem.getUser(userId);
    } else {
      // Route to old system
      return await this.oldSystem.getUser(userId);
    }
  }

  private compareResponses(oldResp: any, newResp: any, userId: string): void {
    const diff = deepDiff(oldResp, newResp);
    if (diff.length > 0) {
      logger.warn(`Response diff for user ${userId}:`, diff);
      metrics.incrementDiffRate('users-v2');
    }
  }
}

// ✅ Fitness function: Track migration progress
export async function checkMigrationProgress(): Promise<void> {
  const routes = await getAllRoutes();
  const migratedRoutes = routes.filter(r => r.usesNewSystem);
  const progressPct = (migratedRoutes.length / routes.length) * 100;

  // ✅ Fail if no progress in 30 days (prevent stalls)
  const lastMigrationDate = await getLastMigrationDate();
  const daysSinceUpdate = Math.floor(
    (Date.now() - lastMigrationDate.getTime()) / (1000 * 60 * 60 * 24)
  );

  if (daysSinceUpdate > 30 && progressPct < 100) {
    console.error(`❌ Migration stalled: no updates in ${daysSinceUpdate} days`);
    console.error(`   Progress: ${progressPct.toFixed(1)}% (${migratedRoutes.length}/${routes.length})`);
    process.exit(1);
  }

  console.log(`✅ Migration progress: ${progressPct.toFixed(1)}%`);
}

// ✅ Rollout process with clear criteria
/*
Phase 1 (Week 1-2): Shadow mode
  - Run both systems, compare responses
  - Fix bugs in new system until diff rate <1%
  - No user impact

Phase 2 (Week 3-4): 5% canary
  - Route 5% of traffic to new system
  - Monitor: error rate <2x, latency <10% increase
  - If metrics good for 1 week, advance

Phase 3 (Week 5-6): 25% canary
  - Same criteria, monitor for 1 week

Phase 4 (Week 7-8): 50% canary
  - Same criteria, monitor for 1 week

Phase 5 (Week 9-10): 100% cutover
  - All traffic to new system
  - Keep old system running for 30 days

Phase 6 (Week 14): Decommission
  - Remove old system code after 30 days with no rollbacks
*/

// ✅ Key Patterns:
// 1. Feature flags: LaunchDarkly/Unleash for runtime routing decisions (instant rollback)
// 2. Shadow mode: Validate new system with zero user impact before canary
// 3. Canary rollout: Gradual percentage increase (5→25→50→100) with automatic fallback
// 4. Dual writes: Update both databases to maintain consistency during migration
// 5. Migration tracking: Fitness function prevents stalls and measures progress objectively
```

## Human Review Checklist

- [ ] **Feature Flag Integration** — Client handles SDK and environment variable fallback, defaults to old system on errors (verify caching enabled, test fallback when flag service unavailable, ensure user-specific targeting works)

- [ ] **Proxy Routing Logic** — Three modes implemented (shadow, canary, full), automatic fallback to old system on new system errors (verify shadow mode returns old response, test fallback triggers on exceptions, ensure consistent hashing for canary)

- [ ] **Response Comparison** — Shadow mode uses structural diff not JSON.stringify, logs discrepancies without impacting users (verify deep-diff library used, test differences logged clearly, ensure comparison non-blocking)

- [ ] **Canary Rollout** — Clear advancement criteria (error rate <2x, latency <10% increase, business metrics stable), automatic rollback if thresholds exceeded (validate monitoring dashboards exist, test rollback triggers, ensure manual override capability)

- [ ] **Data Consistency** — Dual writes update both databases atomically where possible, backfill scripts idempotent (verify maximum lag documented if eventual consistency, test data stays synchronized, ensure backfill safe to re-run)

- [ ] **Migration Progress Tracking** — Fitness function measures percentage of endpoints migrated, fails if no progress in 30 days (verify git blame detects stalls, test reports accurate percentage, ensure historical trend data collected)

---

**Key Takeaway**: The Strangler Fig pattern succeeds because every step is reversible, monitored, and validated before advancing; never rush canary rollout—spend 2 weeks in shadow mode validating behavior before exposing users to new system.
