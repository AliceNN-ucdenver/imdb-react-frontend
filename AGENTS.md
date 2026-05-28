# Agent Governance Instructions

This repository is governed by **The Red Queen** governance system.

## BAR: IMDB Lite Application (APP-IMDB-001)

- **Governance Tier:** autonomous
- **Composite Score:** 89/100
- **Criticality:** medium
- **Permission Mode:** auto-edit
- **Threat Model Access:** open

## Permissions (Autonomous Tier)

You may implement freely within `src/`. All changes will be validated
by the Red Queen pre-tool hooks automatically.

**Allowed tools:** Edit, Write, Bash, Read, Glob, Grep

## Cross-BAR Dependencies

- **IMDB Celebs** (bar-to-bar)
- **IMDB Identity Service** (bar-to-infrastructure)
- **Image CDN** (bar-to-infrastructure)

## Before Making Changes

1. Call `get_orchestration_decision` to understand your full governance context.
2. Call `get_constraints` to understand your permission tier and boundaries.
3. Call `get_bar_context` to understand the application's architecture,
   governance scores, and active constraints.
4. Call `governance_gaps` to check for existing governance issues.
5. For any structural change (new service, database connection,
   external call), call `validate_action` to verify governance compliance.

## Required Validations

- All proposed structural changes: `validate_action`
- Architecture file validation: `validate_calm`
- Before creating a PR: `governance_gaps()` to check for issues
- Review ADRs with `get_adrs` before making architectural decisions

## Governance Tiers

| Tier | Min Score | Mode | Agents | Human Approval |
|------|----------|------|--------|----------------|
| autonomous | 80% | auto-edit | 1 | No |
| supervised | 50% | ask-edit | 1 | Yes |
| restricted | 0% | plan | 2 | Yes |
