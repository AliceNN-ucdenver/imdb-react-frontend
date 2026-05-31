#!/usr/bin/env node
/**
 * The Red Queen's Court — PreToolUse Hook Validator
 *
 * Called by Claude Code PreToolUse and Copilot preToolUse hooks.
 * Reads .redqueen/policy.json (pre-computed static rules from the mesh)
 * and evaluates tool calls against governance constraints.
 *
 * Claude Code: exit code 2 + stderr blocks a tool call.
 * Copilot: stdout JSON permissionDecision blocks/allows a tool call.
 */
'use strict';

const fs = require('fs');
const path = require('path');

// Read JSON from stdin
let inputData = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { inputData += chunk; });
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(inputData);
    const decision = validate(input);
    emitDecision(input, decision);
  } catch (err) {
    emitHookError(err);
  }
});

function emitHookError(err) {
  const message = err && err.message ? err.message : String(err);
  const reason = '[Red Queen] Hook validation error; failing closed: ' + message;
  const agent = (process.env.AGENT_TYPE || '').toLowerCase();

  if (agent === 'copilot') {
    process.stdout.write(JSON.stringify({
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    }));
    process.exit(0);
  }

  process.stderr.write(reason + '\n');
  process.exit(2);
}

function emitDecision(input, decision) {
  const agent = detectAgent(input);

  // Write per-decision audit line BEFORE emitting so the record is durable
  // even if the agent runtime kills us after stdout. Fail-soft: any error
  // here is swallowed so the hook still enforces.
  try { appendAuditLine(input, decision, agent); } catch (_) { /* fail-soft */ }
  // DIAGNOSTIC (Tier 2.5a) — one-time signing-context probe. Remove after
  // the 2.0 run confirms whether the Ed25519 key is reachable from the hook.
  try { writeSigningProbeOnce(); } catch (_) { /* fail-soft */ }

  if (agent === 'copilot') {
    process.stdout.write(JSON.stringify({
      permissionDecision: decision.allowed ? 'allow' : 'deny',
      permissionDecisionReason: decision.reason,
    }));
    process.exit(0);
  }

  if (!decision.allowed) {
    process.stderr.write(decision.reason + '\n');
    process.exit(2);
  }

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
    },
  }));
  process.exit(0);
}

function writeSigningProbeOnce() {
  // DIAGNOSTIC (Tier 2.5a) — one-time capture of whether the per-epoch
  // Ed25519 signing context is reachable from THIS hook process. The hook
  // runs separately from the runner that owns the ephemeral private key,
  // so this confirms (rather than assumes) what the hook can sign. SAFE:
  // env NAMES + booleans + counts only -- never key material or env values.
  // REMOVE in Tier 2.5a once the 2.0 run confirms the signing context.
  try {
    var probePath = path.join(process.cwd(), '.redqueen', 'hook-signing-probe.jsonl');
    if (fs.existsSync(probePath)) { return; }
    var keysDir = path.join(process.cwd(), '.maintainability', 'audit', 'keys');
    var privCount = 0, pubCount = 0;
    try {
      var files = fs.existsSync(keysDir) ? fs.readdirSync(keysDir) : [];
      for (var i = 0; i < files.length; i++) {
        var lf = files[i].toLowerCase();
        if (lf.indexOf('.pub') !== -1) { pubCount++; }
        else if (lf.indexOf('priv') !== -1 || lf.indexOf('secret') !== -1 || lf.indexOf('.key') !== -1) { privCount++; }
      }
    } catch (_) { /* ignore */ }
    var hints = ['OKR', 'RUN_ID', 'INTENT', 'PHASE', 'EPOCH', 'SIGNER', 'MAINTAINABILITY', 'REDQUEEN', 'SESSION', 'KEY', 'TOKEN', 'SIGN'];
    var envNames = Object.keys(process.env).filter(function (k) {
      var ku = k.toUpperCase();
      for (var j = 0; j < hints.length; j++) { if (ku.indexOf(hints[j]) !== -1) { return true; } }
      return false;
    }).sort();
    var probe = {
      diagnostic: 'tier-2.5a-hook-signing-probe',
      note: 'env NAMES + booleans + counts only; REMOVE after the 2.0 run confirms signing context',
      timestamp: new Date().toISOString(),
      pid: process.pid,
      ppid: typeof process.ppid === 'number' ? process.ppid : null,
      phase: process.env.PHASE || null,
      runId: process.env.RUN_ID || null,
      okrId: process.env.OKR_ID || null,
      intentThread: process.env.INTENT_THREAD_UUID || null,
      signerEpoch: process.env.SIGNER_EPOCH || null,
      runnerSessionEnvVisible: !!(process.env.RUN_ID && process.env.PHASE),
      privKeyOnDisk: privCount,
      pubKeysOnDisk: pubCount,
      envKeysPresent: envNames
    };
    var dir = path.dirname(probePath);
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
    fs.writeFileSync(probePath, JSON.stringify(probe) + '\n');
  } catch (_) { /* fail-soft -- never affect enforcement */ }
}

function appendAuditLine(input, decision, agent) {
  const policyPath = path.join(process.cwd(), '.redqueen', 'policy.json');
  if (!fs.existsSync(policyPath)) { return; }
  let policy;
  try { policy = JSON.parse(fs.readFileSync(policyPath, 'utf8')); } catch (_) { return; }

  const auditCfg = (policy && policy.auditLog) || { enabled: true, path: '.redqueen/audit-log.jsonl' };
  if (auditCfg.enabled === false) { return; }

  const logPath = path.join(process.cwd(), auditCfg.path || '.redqueen/audit-log.jsonl');
  const logDir = path.dirname(logPath);
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const toolName = canonicalToolName(input.tool_name || input.toolName || '');
  const toolInput = parseToolInput(input.tool_input || input.toolArgs || {});
  const filePath = toolInput.file_path || toolInput.filePath || toolInput.path || '';
  const sessionId = process.env.CLAUDE_SESSION_ID ||
    process.env.COPILOT_RUN_ID ||
    process.env.GITHUB_RUN_ID ||
    '';

  const entry = {
    timestamp: new Date().toISOString(),
    action: 'pre_tool_use',
    barId: policy.barId || '',
    barName: policy.barName || '',
    payload: {
      tier: policy.tier || '',
      agent: agent,
      tool: toolName,
      filePath: filePath,
      verdict: decision.allowed ? 'allow' : 'deny',
      reason: decision.reason || '',
      ruleId: decision.ruleId || null,
      // Override metadata: when a would-be deny was flipped to an allow
      // because the operator supplied REDQUEEN_TOOL_APPROVED or
      // REDQUEEN_PLAN_APPROVED (or toolInput.redqueenApproved), the
      // audit line records WHICH rule was bypassed and WHICH approval
      // source granted it. A normal allow leaves these null/false.
      override: decision.override === true,
      bypassedRuleId: decision.bypassedRuleId || null,
      approvalSource: decision.approvalSource || null,
      sessionId: sessionId,
    },
  };

  // JSONL append. Single line, single write — line-atomic on POSIX for
  // payloads under PIPE_BUF (4096 bytes). Hook payload is well under that.
  fs.appendFileSync(logPath, JSON.stringify(entry) + '\n', 'utf8');
}

function detectAgent(input) {
  const envAgent = (process.env.AGENT_TYPE || '').toLowerCase();
  if (envAgent === 'copilot' || envAgent === 'claude') { return envAgent; }

  // Copilot camelCase hook payloads use toolName/toolArgs. Claude and VS Code
  // compatible payloads use tool_name/tool_input.
  if (input.toolName || input.toolArgs) { return 'copilot'; }
  return 'claude';
}

function parseToolInput(value) {
  if (!value) { return {}; }
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return { command: value }; }
  }
  return value;
}

function canonicalToolName(toolName) {
  const normalized = String(toolName || '').toLowerCase();
  const map = {
    bash: 'Bash',
    powershell: 'Bash',
    terminal_command: 'Bash',
    create: 'Write',
    write: 'Write',
    file_create: 'Write',
    edit: 'Edit',
    file_edit: 'Edit',
    view: 'Read',
    read: 'Read',
    glob: 'Glob',
    grep: 'Grep',
    web_fetch: 'WebFetch',
    webfetch: 'WebFetch',
    web_search: 'WebSearch',
    websearch: 'WebSearch',
    task: 'Agent',
    agent: 'Agent',
  };
  return map[normalized] || toolName || '';
}

function validate(input) {
  const rawToolName = input.tool_name || input.toolName || '';
  const toolName = canonicalToolName(rawToolName);
  const toolInput = parseToolInput(input.tool_input || input.toolArgs || {});

  // Load policy.json
  const policyPath = path.join(process.cwd(), '.redqueen', 'policy.json');
  if (!fs.existsSync(policyPath)) {
    return {
      allowed: false,
      reason: '[Red Queen] Missing .redqueen/policy.json; failing closed. Re-run the Red Queen scaffold or doctor.',
    };
  }

  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  const tier = policy.tier;
  const rules = policy.rules || {};

  // Skip validation for read-only tools after policy is loaded successfully.
  const readOnlyTools = ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch', 'Agent'];
  if (readOnlyTools.includes(toolName)) {
    return { allowed: true, reason: '[Red Queen] Read-only tool allowed.' };
  }

  // Check tool restrictions for this tier
  const tierRules = rules.toolRestrictions && rules.toolRestrictions[tier];
  if (tierRules) {
    if (tierRules.deny && tierRules.deny.includes(toolName)) {
      return {
        allowed: false,
        ruleId: 'TIER-001',
        reason:
          '[Red Queen] Tool "' + toolName + '" is denied for ' + tier +
          '-tier BARs (score: ' + policy.compositeScore + '/100). ' +
          'Improve governance scores or get approval first.',
      };
    }
  }

  // Track pending overrides so we can attribute the bypass on the audit
  // line even though the final verdict is allow. If a later check denies,
  // that deny is recorded as-is (no override claim) and pendingOverride
  // is discarded.
  let pendingOverride = null;

  function approvalSourceLabel() {
    if (process.env.REDQUEEN_PLAN_APPROVED === 'true') { return 'REDQUEEN_PLAN_APPROVED'; }
    if (process.env.REDQUEEN_TOOL_APPROVED === 'true') { return 'REDQUEEN_TOOL_APPROVED'; }
    if (toolInput.redqueenApproved === true) { return 'toolInput.redqueenApproved'; }
    return null;
  }

  if (tier === 'restricted' && toolName === 'Edit') {
    const planApproved = process.env.REDQUEEN_PLAN_APPROVED === 'true' ||
      toolInput.redqueenApproved === true;
    if (!planApproved) {
      return {
        allowed: false,
        ruleId: 'TIER-002',
        reason:
          '[Red Queen] Restricted-tier BARs are plan-first. Edit is blocked until ' +
          'human approval is recorded (set REDQUEEN_PLAN_APPROVED=true for approved runs).',
      };
    }
    // Approval flipped a deny into an allow. Capture the override so the
    // audit-log line records WHICH rule was bypassed and WHICH source
    // granted it. Note: REDQUEEN_TOOL_APPROVED alone does NOT bypass
    // TIER-002 (restricted plan-first); only PLAN_APPROVED or the
    // per-call toolInput flag does.
    pendingOverride = {
      bypassedRuleId: 'TIER-002',
      approvalSource: process.env.REDQUEEN_PLAN_APPROVED === 'true'
        ? 'REDQUEEN_PLAN_APPROVED'
        : 'toolInput.redqueenApproved',
    };
  }

  const hasApproval = process.env.REDQUEEN_TOOL_APPROVED === 'true' ||
    process.env.REDQUEEN_PLAN_APPROVED === 'true' ||
    toolInput.redqueenApproved === true;
  if (tierRules && tierRules.requireApproval && tierRules.requireApproval.includes(toolName)) {
    if (!hasApproval) {
      return {
        allowed: false,
        ruleId: 'TIER-003',
        reason:
          '[Red Queen] Tool "' + toolName + '" requires approval for ' + tier +
          '-tier BARs. Record approval with REDQUEEN_TOOL_APPROVED=true or toolInput.redqueenApproved=true.',
      };
    }
    // Approval flipped a would-be TIER-003 deny into an allow. Override
    // the in-flight pendingOverride only if TIER-003 is the rule that
    // actually got bypassed here (TIER-002 takes precedence when both
    // apply, since plan-first is the stricter gate).
    if (!pendingOverride) {
      pendingOverride = {
        bypassedRuleId: 'TIER-003',
        approvalSource: approvalSourceLabel(),
      };
    }
  }

  // Check file path restrictions
  const filePath = toolInput.file_path || toolInput.filePath || toolInput.path || toolInput.command || '';
  if (filePath && rules.readOnlyPaths) {
    for (const pattern of rules.readOnlyPaths) {
      if (matchGlob(filePath, pattern)) {
        return {
          allowed: false,
          ruleId: 'CTRL-001',
          reason:
            '[Red Queen] File "' + filePath + '" is governance-managed (read-only). ' +
            'Re-run scaffold_agent_config to update.',
        };
      }
    }
  }

  // Check security-critical paths for restricted tier
  if (tier === 'restricted' && filePath && rules.securityCriticalPaths) {
    for (const pattern of rules.securityCriticalPaths) {
      if (matchGlob(filePath, pattern)) {
        return {
          allowed: false,
          ruleId: 'SEC-001',
          reason:
            '[Red Queen] File "' + filePath + '" is security-critical and cannot be ' +
            'modified by restricted-tier agents.',
        };
      }
    }
  }

  const sourceNode = toolInput.sourceNode || toolInput.source_node;
  const targetNode = toolInput.targetNode || toolInput.target_node;
  if (sourceNode && targetNode && Array.isArray(rules.allowedConnections)) {
    const allowed = rules.allowedConnections.some(function (conn) {
      return conn.source === sourceNode && conn.target === targetNode;
    });
    if (!allowed) {
      return {
        allowed: false,
        ruleId: 'CALM-004',
        reason:
          '[Red Queen] CALM-004: No declared CALM relationship permits ' +
          sourceNode + ' -> ' + targetNode + '. Route through a declared interface or update the architecture first.',
      };
    }
  }

  // Custom team rules. Walk customRules and deny on first regex hit.
  //
  // Two distinct contracts because Edit/Write and Bash are different:
  //
  //   - Edit / Write: appliesTo is a list of file globs. The walker
  //     globs the target file path against each entry; on a hit, it
  //     regex-tests denyPattern against the proposed content
  //     (new_string for Edit, content for Write).
  //
  //   - Bash: there is no file path; commands are strings. The walker
  //     considers a rule applicable to Bash if appliesTo is empty or
  //     contains '**' (the catch-all idioms). Anything else is treated
  //     as Edit/Write-only and skipped for Bash. When applicable, the
  //     walker regex-tests denyPattern against the command text.
  //
  // Pathological regex compile errors are caught and the rule is
  // skipped with a stderr warning. Runtime regex cost is not bounded;
  // teams are responsible for non-pathological patterns.
  const customRules = Array.isArray(rules.customRules) ? rules.customRules : [];
  if (customRules.length > 0) {
    // CustomRule walker uses its own path/content variables, separate
    // from the read-only-paths filePath (which deliberately includes
    // command-as-pseudo-path so Bash hitting .redqueen/** denies).
    const customRulePath = toolInput.file_path || toolInput.filePath || toolInput.path || '';
    const customRuleContent =
      (toolName === 'Edit' && (toolInput.new_string || toolInput.newContent || '')) ||
      (toolName === 'Write' && (toolInput.content || toolInput.new_string || '')) ||
      (toolName === 'Bash' && (toolInput.command || '')) ||
      '';

    for (var i = 0; i < customRules.length; i++) {
      var rule = customRules[i];
      if (!rule || !rule.id || !rule.denyPattern) { continue; }

      var appliesTo = Array.isArray(rule.appliesTo) ? rule.appliesTo : [];
      var pathMatches = false;
      if (toolName === 'Bash') {
        // Bash rules opt in via empty appliesTo or '**' catch-all. Any
        // other glob is treated as Edit/Write-only.
        pathMatches = appliesTo.length === 0 || appliesTo.indexOf('**') !== -1;
      } else if (customRulePath) {
        // Edit / Write: glob-match the target file path.
        for (var j = 0; j < appliesTo.length; j++) {
          if (matchGlob(customRulePath, appliesTo[j])) { pathMatches = true; break; }
        }
      }
      if (!pathMatches) { continue; }

      var re;
      try { re = new RegExp(rule.denyPattern); } catch (err) {
        process.stderr.write('[Red Queen] customRule ' + rule.id + ' has invalid regex; skipping.\n');
        continue;
      }

      if (re.test(customRuleContent)) {
        return {
          allowed: false,
          ruleId: rule.id,
          reason: '[Red Queen] ' + rule.id + ': ' + (rule.message || 'custom rule denial'),
        };
      }
    }
  }

  // Allow. If an earlier check was approval-bypassed, the audit-log
  // line records the override metadata (which rule was bypassed and
  // which approval source granted it).
  const finalAllow = { allowed: true, reason: '[Red Queen] Policy checks passed.' };
  if (pendingOverride) {
    finalAllow.override = true;
    finalAllow.bypassedRuleId = pendingOverride.bypassedRuleId;
    finalAllow.approvalSource = pendingOverride.approvalSource;
    finalAllow.reason = '[Red Queen] Approved override: ' + pendingOverride.bypassedRuleId +
      ' bypassed via ' + pendingOverride.approvalSource + '.';
  }
  return finalAllow;
}

function matchGlob(filePath, pattern) {
  const normalized = filePath.replace(/\\/g, '/');
  const regex = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '{{DS}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{DS\}\}/g, '.*');
  return new RegExp('^' + regex + '$').test(normalized);
}
