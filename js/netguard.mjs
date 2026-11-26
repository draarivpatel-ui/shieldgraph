// SSRF, egress allowlist, homoglyph host and exfiltration checks for URLs.
import { shannonEntropy } from './util.mjs';
import { foldConfusables, decodePercent } from './deobfuscate.mjs';

export const ALLOWED_SCHEMES = ['http:', 'https:'];

// [network, prefix length, label]
export const PRIVATE_V4 = [
  ['0.0.0.0', 8, 'unspecified or "this host" range'],
  ['10.0.0.0', 8, 'private network (RFC 1918)'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local and cloud metadata'],
  ['172.16.0.0', 12, 'private network (RFC 1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.168.0.0', 16, 'private network (RFC 1918)'],
  ['198.18.0.0', 15, 'benchmark network'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
  ['255.255.255.255', 32, 'broadcast']
];

export const PRIVATE_V6 = [
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['fc00::', 7, 'unique local'],
  ['fe80::', 10, 'link-local'],
  ['fec0::', 10, 'site-local (deprecated)'],
  ['ff00::', 8, 'multicast'],
  ['2001:db8::', 32, 'documentation'],
  ['fd00:ec2::254', 128, 'cloud metadata (IPv6)']
];

export const INTERNAL_HOST_SUFFIXES = ['localhost', 'local', 'internal', 'intranet', 'corp', 'home.arpa', 'lan'];
export const METADATA_HOSTS = ['metadata.google.internal', 'metadata', 'instance-data', 'metadata.azure.internal'];

export function parseIPv4(host) {
  const parts = String(host).split('.');
  if (parts.length !== 4) return null;
  const out = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

function v4ToInt(parts) {
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function ipv4InCidr(parts, network, prefix) {
  const base = parseIPv4(network);
  if (!parts || !base) return false;
  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1)) >>> 0;
  return ((v4ToInt(parts) & mask) >>> 0) === ((v4ToInt(base) & mask) >>> 0);
}

// Parses any IPv6 text form to 8 sixteen-bit groups, including an embedded IPv4 tail.
export function parseIPv6(input) {
  let host = String(input).replace(/^\[|\]$/g, '').toLowerCase();
  const zone = host.indexOf('%');
  if (zone !== -1) host = host.slice(0, zone);
  if (!host.includes(':')) return null;
  let tail = [];
  const lastColon = host.lastIndexOf(':');
  const lastPart = host.slice(lastColon + 1);
  if (lastPart.includes('.')) {
    const v4 = parseIPv4(lastPart);
    if (!v4) return null;
    tail = [(v4[0] << 8) + v4[1], (v4[2] << 8) + v4[3]];
    host = `${host.slice(0, lastColon + 1)}0:0`;
  }
  const halves = host.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (s) => (s ? s.split(':') : []).map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  const head = parseGroups(halves[0]);
  const rest = halves.length === 2 ? parseGroups(halves[1]) : [];
  if ([...head, ...rest].some(Number.isNaN)) return null;
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  } else groups = head;
  if (groups.length !== 8) return null;
  if (tail.length) {
    groups[6] = tail[0];
    groups[7] = tail[1];
  }
  return groups;
}

export function ipv6InCidr(groups, network, prefix) {
  const base = parseIPv6(network);
  if (!groups || !base) return false;
  let bits = prefix;
  for (let i = 0; i < 8; i += 1) {
    if (bits <= 0) return true;
    const take = Math.min(16, bits);
    const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
    if ((groups[i] & mask) !== (base[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

// Returns the IPv4 address hidden inside an IPv6 literal (mapped, compatible, NAT64, 6to4).
export function embeddedIPv4(groups) {
  if (!groups) return null;
  const toV4 = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255];
  const zeros = (n) => groups.slice(0, n).every((g) => g === 0);
  if (zeros(5) && groups[5] === 0xffff) return toV4(groups[6], groups[7]);
  if (zeros(6) && (groups[6] || groups[7] > 1)) return toV4(groups[6], groups[7]);
  if (groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0)) return toV4(groups[6], groups[7]);
  if (groups[0] === 0x2002) return toV4(groups[1], groups[2]);
  return null;
}

export function classifyIp(host) {
  const bare = String(host).replace(/^\[|\]$/g, '');
  const v4 = parseIPv4(bare);
  if (v4) {
    for (const [network, prefix, label] of PRIVATE_V4) {
      if (ipv4InCidr(v4, network, prefix)) return { family: 4, private: true, range: `${network}/${prefix}`, label, address: v4.join('.') };
    }
    return { family: 4, private: false, address: v4.join('.') };
  }
  const v6 = parseIPv6(bare);
  if (v6) {
    const inner = embeddedIPv4(v6);
    if (inner) {
      const innerClass = classifyIp(inner.join('.'));
      if (innerClass.private) return { ...innerClass, family: 6, label: `${innerClass.label} (IPv4 embedded in IPv6)`, address: bare };
    }
    for (const [network, prefix, label] of PRIVATE_V6) {
      if (ipv6InCidr(v6, network, prefix)) return { family: 6, private: true, range: `${network}/${prefix}`, label, address: bare };
    }
    return { family: 6, private: false, address: bare };
  }
  return null;
}

// RFC 3492 Punycode decoder for xn-- labels.
export function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  let n = 128, i = 0, bias = 72;
  const basicEnd = input.lastIndexOf('-');
  const output = basicEnd > 0 ? [...input.slice(0, basicEnd)].map((c) => c.codePointAt(0)) : [];
  const digit = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base);
  const adapt = (delta, numPoints, first) => {
    let d = first ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((base - tMin) * tMax) >> 1) {
      d = Math.floor(d / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * d) / (d + skew));
  };
  for (let index = basicEnd > 0 ? basicEnd + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (index >= input.length) return null;
      const d = digit(input.charCodeAt(index++));
      if (d >= base) return null;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
      if (w > 1e9) return null;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) return null;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

export function unicodeHost(host) {
  return String(host)
    .split('.')
    .map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label;
      const decoded = punycodeDecode(label.slice(4));
      return decoded === null ? label : decoded;
    })
    .join('.');
}

// Lookalike skeleton used only to compare two hostnames visually.
export function hostSkeleton(host) {
  return foldConfusables(String(host).normalize('NFKC').toLowerCase()).text
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[0]/g, 'o')
    .replace(/[1|]/g, 'l')
    .replace(/5/g, 's');
}

export function hostMatches(host, domain) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  const d = String(domain).toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  return h === d || h.endsWith(`.${d}`);
}

export function isAllowedHost(host, allowlist = []) {
  return allowlist.some((domain) => hostMatches(host, domain));
}

const SECRET_PARAM = /(^|[_-])(token|secret|password|passwd|pwd|key|apikey|api_key|auth|session|cookie|credential|cred|bearer|sig|signature|private)([_-]|$)/i;

export function looksLikeSecretValue(value) {
  const v = String(value);
  if (v.length < 16) return false;
  if (/^[0-9]+$/.test(v)) return false;
  const entropy = shannonEntropy(v);
  if (/^[0-9a-f]+$/i.test(v)) return v.length >= 24 && entropy >= 3.2;
  return entropy >= 3.6 && /[0-9]/.test(v) && /[A-Za-z]/.test(v);
}

// Finds data encoded into DNS labels (long, high-entropy subdomains).
export function dnsExfilLabels(host) {
  const labels = String(host).toLowerCase().split('.');
  if (labels.length < 3) return [];
  return labels.slice(0, -2).filter((label) => {
    if (label.length >= 40) return true;
    if (label.length < 20) return false;
    const entropy = shannonEntropy(label);
    return (/^[0-9a-f]+$/.test(label) && entropy >= 3.0) || entropy >= 3.8;
  });
}

function rawHostOf(urlText) {
  const m = String(urlText).match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^/?#:]*)/i);
  return m ? m[1] : '';
}

/**
 * Analyzes one URL. Returns { ok, url, host, findings[] } where each finding has
 * { rule, severity, message }.
 * @param {string} urlText
 * @param {{egressAllow?: string[], knownSecrets?: string[], protectedBrands?: string[]}} options
 */
export function analyzeUrl(urlText, options = {}) {
  const findings = [];
  const allow = options.egressAllow || [];
  const secrets = (options.knownSecrets || []).filter((s) => String(s).length >= 8);
  let parsed;
  try {
    parsed = new URL(String(urlText).trim());
  } catch {
    findings.push({ rule: 'malformedUrl', severity: 'medium', message: 'URL could not be parsed; failing closed.' });
    return { ok: false, url: urlText, host: '', findings };
  }
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    findings.push({ rule: 'blockedScheme', severity: 'high', message: `Scheme ${parsed.protocol} is not http or https.` });
  }
  const host = parsed.hostname.replace(/\.$/, '').toLowerCase();
  if (parsed.username || parsed.password) {
    findings.push({ rule: 'userinfoConfusion', severity: 'high', message: `URL carries userinfo "${parsed.username}" before "@", so the real host is ${host}.` });
  }
  const rawHost = rawHostOf(urlText).replace(/\.$/, '').toLowerCase();
  const ipClass = classifyIp(host);
  if (ipClass) {
    const literal = rawHost.replace(/^\[|\]$/g, '');
    const canonical = host.replace(/^\[|\]$/g, '');
    if (literal && literal !== canonical && ipClass.family === 4) {
      findings.push({ rule: 'obfuscatedIp', severity: 'high', message: `Host "${rawHost}" is an encoded form of ${ipClass.address}.` });
    }
    if (ipClass.private) {
      findings.push({ rule: 'ssrf', severity: 'critical', message: `${ipClass.address} is in ${ipClass.range || 'a private range'} (${ipClass.label}).` });
    }
  } else if (host) {
    if (METADATA_HOSTS.includes(host) || INTERNAL_HOST_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) {
      findings.push({ rule: 'ssrf', severity: 'critical', message: `${host} is an internal or metadata hostname.` });
    }
    const uni = unicodeHost(host);
    if (uni !== host || /[^\x00-\x7f]/.test(uni)) {
      const skeleton = hostSkeleton(uni);
      const brands = [...allow, ...(options.protectedBrands || [])];
      const spoofed = brands.find((b) => hostSkeleton(b) === skeleton || skeleton.endsWith(`.${hostSkeleton(b)}`));
      findings.push(spoofed
        ? { rule: 'homoglyphHost', severity: 'critical', message: `${host} renders as "${uni}", a lookalike of ${spoofed}.` }
        : { rule: 'idnHost', severity: 'medium', message: `${host} is an internationalized name ("${uni}").` });
    } else {
      const skeleton = hostSkeleton(host);
      const brands = [...allow, ...(options.protectedBrands || [])];
      const spoofed = brands.find((b) => !hostMatches(host, b) && hostSkeleton(b) === skeleton);
      if (spoofed) findings.push({ rule: 'homoglyphHost', severity: 'critical', message: `${host} imitates ${spoofed} with lookalike ASCII.` });
    }
  }
  if (host && !ipClass?.private && !isAllowedHost(host, allow) && ALLOWED_SCHEMES.includes(parsed.protocol)) {
    findings.push({ rule: 'egressNotAllowed', severity: 'medium', message: `${host} is not on the egress allowlist.` });
  }
  const labels = dnsExfilLabels(host);
  if (labels.length) {
    findings.push({ rule: 'dnsExfil', severity: 'critical', message: `Subdomain label "${labels[0].slice(0, 24)}..." looks like encoded data (${labels[0].length} chars).` });
  }
  const decodedUrl = decodePercent(parsed.href).text;
  for (const [key, value] of parsed.searchParams) {
    if (SECRET_PARAM.test(key) && value.length >= 6) {
      findings.push({ rule: 'secretExfil', severity: 'critical', message: `Query parameter "${key}" carries a credential-like value.` });
    } else if (looksLikeSecretValue(value)) {
      findings.push({ rule: 'secretExfil', severity: 'high', message: `Query parameter "${key}" carries a high-entropy value (${value.length} chars).` });
    }
  }
  for (const secret of secrets) {
    if (decodedUrl.includes(secret) || parsed.href.includes(encodeURIComponent(secret)) || host.includes(String(secret).toLowerCase())) {
      findings.push({ rule: 'secretExfil', severity: 'critical', message: 'URL contains a secret value read earlier in this session.' });
      break;
    }
    const secretBytes = [...new TextEncoder().encode(secret)];
    const hex = secretBytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    const b64 = btoa(String.fromCharCode(...secretBytes)).replace(/=+$/, '');
    if (decodedUrl.toLowerCase().includes(hex.slice(0, 24)) || decodedUrl.includes(b64.slice(0, 16))) {
      findings.push({ rule: 'secretExfil', severity: 'critical', message: 'URL contains an encoded copy of a secret read earlier in this session.' });
      break;
    }
  }
  return { ok: true, url: parsed.href, host, unicode: unicodeHost(host), findings };
}

export function extractUrls(text) {
  const out = [];
  for (const m of String(text).matchAll(/\b(?:https?|ftp|file|gopher|dict|ldap|data|javascript):[^\s"'<>)\]]+/gi)) {
    out.push(m[0].replace(/[.,;:!?]+$/, ''));
  }
  return out;
}
