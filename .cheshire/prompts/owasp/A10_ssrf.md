# Server-Side Request Forgery (SSRF) — Compact Remediation Guide

## What is SSRF?

SSRF occurs when applications fetch remote resources without validating user-supplied URLs, allowing attackers to access internal services, cloud metadata, or private networks bypassing firewalls.

## STRIDE Mapping

- **Primary**: Tampering (attackers manipulate server to make unauthorized requests)
- **Secondary**: Information Disclosure (SSRF exposes internal services/metadata), Elevation of Privilege (accessing cloud credentials)

## Types/Patterns of SSRF

- **Internal Service Access**: Fetching `http://localhost:8080/admin` to access internal services
- **Cloud Metadata Exposure**: Accessing `http://169.254.169.254/latest/meta-data/` for AWS credentials
- **Private Network Scanning**: Using SSRF to scan internal network `http://192.168.1.0/24`
- **DNS Rebinding**: Domain initially resolves to public IP, then rebinds to private IP
- **Protocol Smuggling**: Using `file:///etc/passwd` or `gopher://` protocols
- **IP Format Bypass**: Alternative representations like `http://127.1` or `http://2130706433`

## What It Looks Like (TypeScript)

```typescript
// ❌ CRITICAL: SSRF - fetches arbitrary URLs
import fetch from 'node-fetch';

export async function fetchWebhook(url: string): Promise<string> {
  const response = await fetch(url); // ❌ No validation!
  return await response.text();
}

// Attack examples:
// fetchWebhook('http://localhost:8080/admin') // Internal admin
// fetchWebhook('http://169.254.169.254/latest/meta-data/iam/security-credentials/') // AWS creds
// fetchWebhook('file:///etc/passwd') // Local files
```

## What Good Looks Like (TypeScript)

```typescript
// ✅ SECURE: Comprehensive SSRF protection with defense in depth
import { URL } from 'url';
import dns from 'dns/promises';
import ipaddr from 'ipaddr.js';
import fetch from 'node-fetch';

// ✅ Domain allowlist (deny-by-default)
const ALLOWED_DOMAINS = new Set([
  'api.github.com',
  'api.example.com',
  'cdn.example.com'
]);

// ✅ Private IP ranges (CIDR)
const PRIVATE_IP_RANGES = [
  '127.0.0.0/8',    // Loopback
  '10.0.0.0/8',     // Private Class A
  '172.16.0.0/12',  // Private Class B
  '192.168.0.0/16', // Private Class C
  '169.254.0.0/16', // Link-local (includes metadata)
  '::1/128',        // IPv6 loopback
  'fc00::/7',       // IPv6 private
  'fe80::/10'       // IPv6 link-local
];

// ✅ Cloud metadata endpoints
const METADATA_ENDPOINTS = [
  '169.254.169.254',           // AWS, Azure, GCP
  'metadata.google.internal',
  'metadata.azure.com'
];

// ✅ Check if IP is private
function isPrivateIP(ip: string): boolean {
  try {
    const addr = ipaddr.parse(ip);

    for (const range of PRIVATE_IP_RANGES) {
      const cidr = ipaddr.parseCIDR(range);
      if (addr.kind() === cidr[0].kind() && addr.match(cidr)) {
        return true;
      }
    }

    return false;
  } catch {
    return true; // Treat parsing failures as suspicious
  }
}

// ✅ Validate URL format and protocol
function validateURL(urlString: string): URL {
  let parsedUrl: URL;

  try {
    parsedUrl = new URL(urlString);
  } catch {
    throw new Error('Invalid URL format');
  }

  // ✅ Only allow http and https
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    console.warn('SSRF blocked: invalid protocol', { protocol: parsedUrl.protocol });
    throw new Error('Only http and https protocols allowed');
  }

  return parsedUrl;
}

// ✅ Check domain allowlist
function validateDomain(hostname: string): void {
  const normalized = hostname.toLowerCase();

  // ✅ Block metadata endpoints by hostname
  if (METADATA_ENDPOINTS.includes(normalized)) {
    console.error('SSRF blocked: metadata endpoint', { hostname: normalized });
    throw new Error('Access to metadata endpoints blocked');
  }

  // ✅ Check allowlist
  if (!ALLOWED_DOMAINS.has(normalized)) {
    console.warn('SSRF blocked: domain not in allowlist', { hostname: normalized });
    throw new Error(`Domain ${hostname} not in allowlist`);
  }
}

// ✅ Resolve DNS and validate IPs
async function validateIPAddress(hostname: string): Promise<void> {
  let addresses: string[];

  try {
    addresses = await dns.resolve(hostname);
  } catch (err) {
    console.warn('DNS resolution failed', { hostname, error: err });
    throw new Error(`DNS resolution failed for ${hostname}`);
  }

  // ✅ Validate each resolved IP
  for (const ip of addresses) {
    if (isPrivateIP(ip)) {
      console.error('SSRF blocked: private IP', { hostname, resolvedIP: ip });
      throw new Error(`Hostname resolves to private IP: ${ip}`);
    }

    if (METADATA_ENDPOINTS.includes(ip)) {
      console.error('SSRF blocked: metadata IP', { hostname, resolvedIP: ip });
      throw new Error('Hostname resolves to metadata endpoint');
    }
  }
}

// ✅ Safe fetch with comprehensive SSRF protection
export async function fetchRemoteResource(urlString: string): Promise<string> {
  try {
    // ✅ Layer 1: Validate URL format and protocol
    const parsedUrl = validateURL(urlString);

    // ✅ Layer 2: Validate domain against allowlist
    validateDomain(parsedUrl.hostname);

    // ✅ Layer 3: Resolve DNS and validate IPs
    await validateIPAddress(parsedUrl.hostname);

    // ✅ Layer 4: Fetch with security controls
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout

    const response = await fetch(parsedUrl.toString(), {
      signal: controller.signal,
      redirect: 'error', // ✅ Disable automatic redirects
      headers: { 'User-Agent': 'SecureApp/1.0' }
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    // ✅ Layer 5: Validate response size
    const contentLength = response.headers.get('content-length');
    const MAX_SIZE = 10 * 1024 * 1024; // 10MB

    if (contentLength && parseInt(contentLength) > MAX_SIZE) {
      throw new Error('Response size exceeds limit');
    }

    const text = await response.text();

    if (text.length > MAX_SIZE) {
      throw new Error('Response size exceeds limit');
    }

    console.info('External request completed', {
      hostname: parsedUrl.hostname,
      status: response.status,
      size: text.length
    });

    return text;

  } catch (err) {
    console.error('SSRF prevention triggered', {
      url: urlString,
      error: err instanceof Error ? err.message : 'Unknown'
    });

    // ✅ Send alert for suspicious patterns
    if (err instanceof Error &&
        (err.message.includes('metadata') ||
         err.message.includes('private IP'))) {
      console.error('🚨 SECURITY ALERT: SSRF attempt', { url: urlString });
    }

    // ✅ Generic error to client
    throw new Error('Failed to fetch resource');
  }
}

// ✅ Key Patterns:
// 1. URL format and protocol validation (http/https only)
// 2. Domain allowlist enforced (deny-by-default)
// 3. Private IP ranges blocked (RFC1918, loopback, link-local)
// 4. Cloud metadata endpoints blocked (169.254.169.254)
// 5. DNS resolution validated before request
// 6. Request timeout enforced (5 seconds)
// 7. Response size limited (10MB)
// 8. Redirects disabled (prevent redirect to internal)
```

## Human Review Checklist

- [ ] **URL Validation** — All URLs parsed using Node.js URL class, protocol restricted to http/https only rejecting file://, gopher://, ftp:// (test submit file:///etc/passwd, gopher://, data:, javascript: verify all blocked)

- [ ] **Domain Allowlist** — Deny-by-default allowlist where only explicitly permitted domains accessible, domains normalized to lowercase (test attempt localhost, internal IPs, external domains not in allowlist verify all blocked)

- [ ] **Private IP Blocking** — All RFC1918 ranges blocked (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback 127.0.0.0/8, link-local 169.254.0.0/16, IPv6 equivalents using ipaddr.js (test attempt 127.0.0.1, 127.1, 10.0.0.1, 192.168.1.1, 169.254.169.254, [::1] verify all blocked)

- [ ] **Metadata Endpoint Protection** — All cloud metadata endpoints blocked (169.254.169.254, metadata.google.internal, metadata.azure.com), both hostname and resolved IP checked (test attempt 169.254.169.254, metadata.google.internal directly and via DNS verify blocked and logged)

- [ ] **DNS Validation** — Hostname resolved to IPs using dns.promises.resolve(), every IP validated against private ranges and metadata endpoints before HTTP request (test create domain resolving to private IP or 169.254.169.254 verify blocked)

- [ ] **Redirect Handling** — Automatic redirect following disabled using redirect: 'error', if redirects needed validated through full validation chain (test allowed domain redirecting to localhost or metadata endpoint verify redirect blocked)

---

**Key Takeaway**: SSRF in cloud environments can lead to full account compromise - validate URL format, enforce domain allowlist, block private IPs and metadata endpoints, resolve and validate DNS, disable redirects, and implement timeout/size limits.
