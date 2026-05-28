#!/usr/bin/env node
/**
 * The Red Queen MCP Runner
 *
 * Repo-local launcher for the live governance mesh. The code repo keeps a
 * self-contained governance harness; the governance mesh remains the source of
 * truth and is resolved locally at runtime.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const manifestPath = path.join(repoRoot, '.redqueen', 'config-manifest.yaml');
const envKeys = ['RED_QUEEN_MESH_PATH', 'GOVERNANCE_MESH_PATH', 'MESH_PATH'];

function readManifestValue(key) {
  if (!fs.existsSync(manifestPath)) { return null; }
  const prefix = key + ':';
  const lines = fs.readFileSync(manifestPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith(prefix)) {
      return trimmed.slice(prefix.length).trim().replace(/^["']|["']$/g, '');
    }
  }
  return null;
}

function resolvePath(value) {
  if (!value) { return null; }
  const cleaned = String(value).trim().replace(/^["']|["']$/g, '');
  if (!cleaned) { return null; }
  return path.isAbsolute(cleaned) ? cleaned : path.resolve(repoRoot, cleaned);
}

function isGovernanceMesh(candidate) {
  return Boolean(candidate && fs.existsSync(path.join(candidate, 'mesh.yaml')));
}

function addCandidate(candidates, source, value) {
  const resolved = resolvePath(value);
  if (resolved) {
    candidates.push({ source, path: resolved });
  }
}

function resolveMeshPath() {
  const candidates = [];
  for (const key of envKeys) {
    addCandidate(candidates, key, process.env[key]);
  }

  addCandidate(candidates, 'repo checkout', './governance-mesh');
  addCandidate(
    candidates,
    'manifest',
    readManifestValue('mesh_checkout_path') || readManifestValue('mesh_path')
  );

  const seen = new Set();
  const checked = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.path)) { continue; }
    seen.add(candidate.path);
    checked.push(candidate);
    if (isGovernanceMesh(candidate.path)) {
      return { resolved: candidate, checked };
    }
  }

  return { resolved: null, checked };
}

const result = resolveMeshPath();
if (!result.resolved) {
  process.stderr.write('[Red Queen] Unable to resolve governance mesh.\n');
  process.stderr.write('[Red Queen] Tried:\n');
  for (const candidate of result.checked) {
    process.stderr.write('  - ' + candidate.source + ': ' + candidate.path + '\n');
  }
  process.stderr.write('[Red Queen] Set RED_QUEEN_MESH_PATH or checkout the mesh to ./governance-mesh.\n');
  process.exit(1);
}

const command = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const args = [
  '-y',
  '@maintainabilityai/redqueen-mcp',
  '--mesh-path',
  result.resolved.path,
  ...process.argv.slice(2),
];

const child = spawn(command, args, {
  cwd: repoRoot,
  stdio: 'inherit',
  env: { ...process.env, RED_QUEEN_MESH_PATH: result.resolved.path },
});

child.on('error', (err) => {
  process.stderr.write('[Red Queen] Failed to start MCP server: ' + err.message + '\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code === null ? 1 : code);
});
