# Software and Data Integrity Failures — Compact Remediation Guide

## What is Integrity Failures?

Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations, including unsigned updates, insecure deserialization, and CI/CD compromise.

## STRIDE Mapping

- **Primary**: Tampering (malicious code injected through compromised supply chain)
- **Secondary**: Elevation of Privilege (malicious updates gain system access), Repudiation (unsigned changes have no accountability)

## Types/Patterns of Integrity Failures

- **Unsigned Updates**: Auto-updates download software without signature verification
- **Insecure Deserialization**: Using eval(), pickle, or unsafe YAML with untrusted data
- **No Digital Signatures**: Plugins or code loaded without HMAC or cryptographic signature checks
- **CI/CD Compromise**: Build pipelines without artifact signing or verification
- **Missing Checksums**: Downloaded files used without SHA-256 hash verification
- **Supply Chain Attacks**: Dependencies or build tools compromised injecting malicious code

## What It Looks Like (TypeScript)

```typescript
// ❌ CRITICAL: Loads unsigned plugin from network
export async function loadPlugin(url: string) {
  const response = await fetch(url);
  const code = await response.text();
  return eval(code); // ❌ No verification, executes arbitrary code!
}

// ❌ CRITICAL: Insecure deserialization
export function deserialize(data: string): any {
  return eval(`(${data})`); // ❌ Code injection!
}
// Attack: Attacker compromises CDN, serves malicious plugin
// Attack: Man-in-the-middle modifies plugin during download
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Comprehensive integrity verification
import crypto from 'crypto';
import { z } from 'zod';

interface PluginMetadata {
  name: string;
  url: string;
  version: string;
  signature: string; // HMAC-SHA256
  checksum: string;  // SHA-256 hash
}

// ✅ Allowlist with signatures
const TRUSTED_PLUGINS: Record<string, PluginMetadata> = {
  'analytics': {
    name: 'analytics',
    url: 'https://cdn.example.com/plugins/analytics.js',
    version: '1.0.0',
    signature: 'hmac-sha256-abc123...',
    checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  }
};

// ✅ Get signing key from environment
function getSigningKey(): Buffer {
  const key = process.env.PLUGIN_SIGNING_KEY;
  if (!key) throw new Error('PLUGIN_SIGNING_KEY not configured');
  return Buffer.from(key, 'hex');
}

// ✅ Generate HMAC signature
export function generateSignature(content: string): string {
  const hmac = crypto.createHmac('sha256', getSigningKey());
  hmac.update(content, 'utf8');
  return 'hmac-sha256-' + hmac.digest('hex');
}

// ✅ Verify signature with constant-time comparison
function verifySignature(content: string, expectedSignature: string): boolean {
  const actualSignature = generateSignature(content);

  return crypto.timingSafeEqual(
    Buffer.from(actualSignature),
    Buffer.from(expectedSignature)
  );
}

// ✅ Calculate SHA-256 checksum
export function generateChecksum(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

// ✅ Secure plugin loading with verification
export async function loadPlugin(pluginName: string): Promise<string> {
  // ✅ Check allowlist
  const metadata = TRUSTED_PLUGINS[pluginName];
  if (!metadata) {
    throw new Error(`Plugin '${pluginName}' not in trusted list`);
  }

  const response = await fetch(metadata.url);
  const content = await response.text();

  // ✅ Verify checksum (integrity)
  const actualChecksum = generateChecksum(content);
  if (!crypto.timingSafeEqual(Buffer.from(actualChecksum), Buffer.from(metadata.checksum))) {
    throw new Error('Plugin integrity check failed');
  }

  // ✅ Verify signature (authenticity)
  if (!verifySignature(content, metadata.signature)) {
    throw new Error('Plugin signature verification failed');
  }

  console.info('Plugin verified successfully', { plugin: pluginName });

  return content; // Don't execute with eval!
}

// ✅ Secure deserialization with schema validation
const UserDataSchema = z.object({
  id: z.string().uuid(),
  name: z.string().max(100),
  email: z.string().email()
});

export function deserializeUserData(json: string): UserData {
  // ✅ Use JSON.parse (safe)
  const parsed = JSON.parse(json);

  // ✅ Validate with Zod
  return UserDataSchema.parse(parsed);
}

// ✅ Signed data with timestamp (prevents replay)
interface SignedData<T> {
  data: T;
  signature: string;
  timestamp: string;
}

export function signData<T>(data: T): SignedData<T> {
  const timestamp = new Date().toISOString();
  const payload = JSON.stringify(data) + timestamp;
  const hmac = crypto.createHmac('sha256', getSigningKey());
  hmac.update(payload);

  return {
    data,
    signature: hmac.digest('hex'),
    timestamp
  };
}

export function verifySignedData<T>(signedData: SignedData<T>, maxAgeMs: number = 5 * 60 * 1000): T {
  const payload = JSON.stringify(signedData.data) + signedData.timestamp;
  const hmac = crypto.createHmac('sha256', getSigningKey());
  hmac.update(payload);
  const expectedSignature = hmac.digest('hex');

  // ✅ Verify signature
  if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signedData.signature))) {
    throw new Error('Signature verification failed');
  }

  // ✅ Check timestamp (prevent replay)
  const age = Date.now() - new Date(signedData.timestamp).getTime();
  if (age > maxAgeMs) {
    throw new Error('Signed data expired');
  }

  return signedData.data;
}

// ✅ Key Patterns:
// 1. HMAC-SHA256 signatures for plugins verify authenticity
// 2. SHA-256 checksums verify content integrity
// 3. JSON.parse() + Zod validation, never eval() which executes code
// 4. Timestamp in signed data prevents replay attacks
// 5. Allowlist of trusted resources with expected signatures
```

## Human Review Checklist

- [ ] **Digital Signatures** — All plugins/updates verified using HMAC-SHA256 or digital signatures before execution, signing key stored securely in environment variables (test tamper with one byte of plugin content, verify signature check fails and logs show integrity violation)

- [ ] **Checksum Verification** — SHA-256 checksums calculated for all downloaded files, compared against expected values before use with constant-time comparison (test download file, modify one byte, verify checksum validation fails and file rejected)

- [ ] **Safe Deserialization** — Never use eval(), Function(), or vm.runInContext() with external data; JSON parsed with JSON.parse() and validated with Zod (test attempt malicious payload deserialization, verify safe methods reject them)

- [ ] **Supply Chain Security** — Dependency integrity verified during installation using package-lock.json, npm audit run to check vulnerabilities, GitHub Action versions pinned to specific SHAs (test modify package-lock.json integrity hash verify npm ci fails)

- [ ] **CI/CD Pipeline Security** — Build artifacts signed using HMAC or GPG, signatures verified before deployment, immutable artifacts never modified post-build (test deploy artifact without signature verify deployment fails, tamper post-build verify verification fails)

- [ ] **Replay Attack Prevention** — Timestamp included in all signed data, age validated on verification rejecting data older than threshold (test create signed data, wait past expiration time, attempt use and verify rejection due to age)

---

**Key Takeaway**: Never execute unsigned code or deserialize untrusted data without verification - use HMAC-SHA256 for signatures, SHA-256 for checksums, JSON.parse + Zod for deserialization, and timestamp validation to prevent replay attacks.
