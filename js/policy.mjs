// The policy evaluator. evaluateCall() is the single decision function used by
// the workbench AND by the exported shieldgraph-guard.mjs, so both always agree.
import { ACTIONS, actionRank, strictestAction, collectStrings, combineWeights, longestCommonString, shannonEntropy } from './util.mjs';
import { deobfuscate } from './deobfuscate.mjs';
import { analyzeUrl, extractUrls, hostMatches } from './netguard.mjs';
import { analyzePath, canonicalizePath, SENSITIVE_PATTERNS } from './pathguard.mjs';
import { analyzeShell } from './shell.mjs';
import { scoreInjection } from './injection.mjs';

// Tool catalog: the effect class of every tool and how each argument is read.
export const TOOL_CATALOG = {
  read_file: { effect: 'fs-read', privileged: false, args: { path: 'path' } },
  list_dir: { effect: 'fs-read', privileged: false, args: { path: 'path' } },
  write_file: { effect: 'fs-write', privileged: true, args: { path: 'path-write', content: 'body' } },
  shell_exec: { effect: 'exec', privileged: true, args: { cmd: 'shell' } },
  http_get: { effect: 'egress-read', privileged: false, args: { url: 'url' } },
  browser_open: { effect: 'egress-read', privileged: false, args: { url: 'url' } },
  search_web: { effect: 'egress-read', privileged: false, args: { query: 'text' } },
  http_post: { effect: 'egress-write', privileged: true, args: { url: 'url', body: 'body' } },
  send_email: { effect: 'comms', privileged: true, args: { to: 'recipient', subject: 'text', body: 'body' } },
  transfer_funds: { effect: 'finance', privileged: true, args: { to_account: 'payee', amount: 'amount', memo: 'text' } },
  render_markdown: { effect: 'render', privileged: false, args: { markdown: 'markdown' } }
};

export const EFFECT_LABELS = {
  'fs-read': 'Filesystem read',
  'fs-write': 'Filesystem write',
  exec: 'Host shell',
  'egress-read': 'Network read',
  'egress-write': 'Network write',
  comms: 'Outbound message',
  finance: 'Money movement',
  render: 'Rendered output'
};

// Every rule the evaluator can raise, with its severity and plain meaning.
export const RULES = {
  unknownTool: ['critical', 'Tool is not in the catalog; unknown tools fail closed.'],
  guardError: ['critical', 'The guard itself failed; failing closed.'],
  badArgs: ['high', 'Arguments are missing or not the expected type.'],
  argCap: ['medium', 'An argument is longer than the policy cap.'],
  rateLimit: ['high', 'Tool exceeded its per-session call cap.'],
  ssrf: ['critical', 'Request targets a private, loopback or metadata address.'],
  obfuscatedIp: ['high', 'IP address written in decimal, octal or hex to dodge filters.'],
  blockedScheme: ['high', 'URL scheme other than http or https.'],
  malformedUrl: ['medium', 'URL could not be parsed.'],
  userinfoConfusion: ['high', 'URL hides its real host behind user@host.'],
  egressNotAllowed: ['medium', 'Read from a host outside the egress allowlist.'],
  egressWriteNotAllowed: ['high', 'Data sent to a host outside the egress allowlist.'],
  homoglyphHost: ['critical', 'Hostname is a lookalike of a trusted domain.'],
  idnHost: ['medium', 'Internationalized hostname.'],
  dnsExfil: ['critical', 'Data encoded into DNS labels.'],
  secretExfil: ['critical', 'A secret or credential leaves the machine.'],
  markdownBeacon: ['critical', 'Rendered image would call an outside host with data.'],
  pathTraversal: ['critical', 'Path climbs out of the workspace.'],
  outsideWorkspace: ['medium', 'Path is outside the workspace root.'],
  sensitivePath: ['critical', 'Path is a credential or key file.'],
  persistencePath: ['high', 'Write to a startup, hook or CI file.'],
  installHook: ['high', 'Write adds a package install script.'],
  pipeToShell: ['critical', 'Downloaded or generated text piped into an interpreter.'],
  reverseShell: ['critical', 'Shell bound to a network socket.'],
  destructive: ['high', 'Command can destroy data.'],
  networkTool: ['high', 'Shell command opens a network connection.'],
  privilegeChange: ['high', 'Command changes permissions or schedules code.'],
  symlinkCreate: ['high', 'Command creates a symbolic link.'],
  decodeExec: ['high', 'Command decodes an encoded payload.'],
  inlineInterpreter: ['medium', 'Interpreter runs inline code.'],
  commandSubstitution: ['medium', 'Nested command substitution.'],
  unbalancedQuote: ['medium', 'Unbalanced quotes in a command.'],
  persistenceWrite: ['high', 'Shell redirect into a startup or hook file.'],
  shellMetaFromUntrusted: ['critical', 'Shell operators arrived inside untrusted text (command injection).'],
  taintedExec: ['medium', 'Command text was copied from untrusted content.'],
  untrustedToPrivilegedSink: ['high', 'Untrusted content flows into a privileged tool argument.'],
  unendorsedRecipient: ['high', 'Message recipient was never named by the user.'],
  unendorsedPayee: ['critical', 'Payee or account was never named by the user.'],
  injectedContext: ['high', 'Privileged call made after untrusted text tried to instruct the agent.']
};

export const SEVERITY_WEIGHT = { critical: 0.85, high: 0.5, medium: 0.2, low: 0.05, info: 0 };

const RULE_IDS = Object.keys(RULES);

function severityDefaults(map) {
  const out = {};
  for (const id of RULE_IDS) out[id] = map[RULES[id][0]];
  return out;
}

const DEFAULT_ALLOW = ['github.com', 'githubusercontent.com', 'registry.npmjs.org', 'npmjs.com', 'pypi.org', 'docs.python.org', 'developer.mozilla.org', 'ourco.example'];
const DEFAULT_BRANDS = ['github.com', 'google.com', 'microsoft.com', 'apple.com', 'paypal.com', 'amazon.com', 'stripe.com', 'okta.com'];

function toolTable(base, overrides = {}) {
  const out = {};
  for (const name of Object.keys(TOOL_CATALOG)) {
    out[name] = { action: base, maxArgChars: 8000, maxCalls: 25, ...(overrides[name] || {}) };
  }
  return out;
}

export const PRESETS = {
  permissive: {
    name: 'Permissive',
    version: 1,
    defaultAction: 'deny',
    workspaceRoot: '/workspace',
    homeDir: '/home/dev',
    trustInternal: true,
    injectionThreshold: 0.6,
    egressAllow: DEFAULT_ALLOW,
    protectedBrands: DEFAULT_BRANDS,
    tools: toolTable('allow'),
    rules: { ...severityDefaults({ critical: 'log', high: 'log', medium: 'allow', low: 'allow' }), ssrf: 'deny', reverseShell: 'deny', blockedScheme: 'deny', unknownTool: 'deny', guardError: 'deny' }
  },
  balanced: {
    name: 'Balanced',
    version: 1,
    defaultAction: 'deny',
    workspaceRoot: '/workspace',
    homeDir: '/home/dev',
    trustInternal: true,
    injectionThreshold: 0.5,
    egressAllow: DEFAULT_ALLOW,
    protectedBrands: DEFAULT_BRANDS,
    tools: toolTable('allow', { transfer_funds: { action: 'allow', maxCalls: 3 } }),
    rules: { ...severityDefaults({ critical: 'deny', high: 'require_approval', medium: 'log', low: 'allow' }), injectedContext: 'log', taintedExec: 'log', egressNotAllowed: 'log', idnHost: 'log' }
  },
  zeroTrust: {
    name: 'Zero-Trust',
    version: 1,
    defaultAction: 'deny',
    workspaceRoot: '/workspace',
    homeDir: '/home/dev',
    trustInternal: false,
    injectionThreshold: 0.35,
    egressAllow: DEFAULT_ALLOW,
    protectedBrands: DEFAULT_BRANDS,
    tools: toolTable('allow', {
      shell_exec: { action: 'require_approval', maxCalls: 10 },
      http_post: { action: 'require_approval' },
      send_email: { action: 'require_approval' },
      transfer_funds: { action: 'deny' },
      write_file: { action: 'require_approval' }
    }),
    rules: { ...severityDefaults({ critical: 'deny', high: 'deny', medium: 'require_approval', low: 'log' }), commandSubstitution: 'require_approval' }
  }
};

export const PRESET_ORDER = ['permissive', 'balanced', 'zeroTrust'];

export function clonePolicy(policy) {
  return JSON.parse(JSON.stringify(policy));
}

/**
 * Validates and normalizes a policy object. Unknown keys are errors; missing
 * rule actions fall back to the strictest action so a gap never opens a hole.
 */
export function validatePolicy(input) {
  const errors = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, errors: ['Policy must be a JSON object.'], policy: null };
  }
  const known = ['name', 'version', 'defaultAction', 'workspaceRoot', 'homeDir', 'trustInternal', 'injectionThreshold', 'egressAllow', 'protectedBrands', 'tools', 'rules'];
  for (const key of Object.keys(input)) if (!known.includes(key)) errors.push(`Unknown top-level key "${key}".`);
  const policy = {
    name: typeof input.name === 'string' && input.name.trim() ? input.name.trim().slice(0, 60) : 'Custom',
    version: 1,
    defaultAction: 'deny',
    workspaceRoot: '/workspace',
    homeDir: '/home/dev',
    trustInternal: false,
    injectionThreshold: 0.5,
    egressAllow: [],
    protectedBrands: [],
    tools: {},
    rules: {}
  };
  if (input.version !== undefined && input.version !== 1) errors.push('version must be 1.');
  if (input.defaultAction !== undefined) {
    if (!ACTIONS.includes(input.defaultAction)) errors.push(`defaultAction must be one of ${ACTIONS.join(', ')}.`);
    else policy.defaultAction = input.defaultAction;
  }
  for (const key of ['workspaceRoot', 'homeDir']) {
    if (input[key] !== undefined) {
      if (typeof input[key] !== 'string' || !input[key].startsWith('/')) errors.push(`${key} must be an absolute path.`);
      else policy[key] = canonicalizePath(input[key], { workspaceRoot: '/' }).resolved;
    }
  }
  if (input.trustInternal !== undefined) {
    if (typeof input.trustInternal !== 'boolean') errors.push('trustInternal must be true or false.');
    else policy.trustInternal = input.trustInternal;
  }
  if (input.injectionThreshold !== undefined) {
    const t = input.injectionThreshold;
    if (typeof t !== 'number' || !(t > 0 && t <= 1)) errors.push('injectionThreshold must be a number above 0 and at most 1.');
    else policy.injectionThreshold = t;
  }
  for (const key of ['egressAllow', 'protectedBrands']) {
    if (input[key] !== undefined) {
      if (!Array.isArray(input[key]) || input[key].some((d) => typeof d !== 'string' || !/^(\*\.)?[a-z0-9.-]+\.[a-z0-9-]+\.?$/i.test(d))) {
        errors.push(`${key} must be a list of domain names.`);
      } else policy[key] = input[key].map((d) => d.toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''));
    }
  }
  const tools = input.tools === undefined ? {} : input.tools;
  if (typeof tools !== 'object' || Array.isArray(tools) || tools === null) errors.push('tools must be an object.');
  else {
    for (const [name, spec] of Object.entries(tools)) {
      if (!TOOL_CATALOG[name]) {
        errors.push(`tools.${name} is not a known tool.`);
        continue;
      }
      if (!spec || typeof spec !== 'object') {
        errors.push(`tools.${name} must be an object.`);
        continue;
      }
      const action = spec.action === undefined ? 'allow' : spec.action;
      if (!ACTIONS.includes(action)) errors.push(`tools.${name}.action must be one of ${ACTIONS.join(', ')}.`);
      const maxArgChars = spec.maxArgChars === undefined ? 8000 : spec.maxArgChars;
      const maxCalls = spec.maxCalls === undefined ? 25 : spec.maxCalls;
      if (!Number.isInteger(maxArgChars) || maxArgChars < 1) errors.push(`tools.${name}.maxArgChars must be a positive integer.`);
      if (!Number.isInteger(maxCalls) || maxCalls < 0) errors.push(`tools.${name}.maxCalls must be a whole number.`);
      for (const k of Object.keys(spec)) if (!['action', 'maxArgChars', 'maxCalls'].includes(k)) errors.push(`tools.${name}.${k} is not a known setting.`);
      policy.tools[name] = { action, maxArgChars, maxCalls };
    }
  }
  const rules = input.rules === undefined ? {} : input.rules;
  if (typeof rules !== 'object' || Array.isArray(rules) || rules === null) errors.push('rules must be an object.');
  else {
    for (const [id, action] of Object.entries(rules)) {
      if (!RULES[id]) errors.push(`rules.${id} is not a known rule.`);
      else if (!ACTIONS.includes(action)) errors.push(`rules.${id} must be one of ${ACTIONS.join(', ')}.`);
      else policy.rules[id] = action;
    }
  }
  for (const id of RULE_IDS) if (!policy.rules[id]) policy.rules[id] = 'deny';
  policy.rules.unknownTool = policy.rules.unknownTool === 'allow' ? 'deny' : policy.rules.unknownTool;
  policy.rules.guardError = 'deny';
  return { ok: errors.length === 0, errors, policy: errors.length ? null : policy };
}

// ---------- provenance ----------

function lower(s) {
  return String(s ?? '').toLowerCase();
}

/**
 * Prepares a context once so many calls can be checked cheaply.
 * context = { trusted: string[], untrusted: [{id, origin, text, trust?}], secrets: string[], history: [{tool}] }
 */
export function prepareContext(context = {}, policy = PRESETS.balanced) {
  const trustedText = (context.trusted || []).map((t) => String(t ?? '')).join('\n');
  const sources = [];
  for (const [i, src] of (context.untrusted || []).entries()) {
    const trust = src.trust === 'internal' ? 'internal' : 'untrusted';
    if (trust === 'internal' && policy.trustInternal) continue;
    const injection = scoreInjection(src.text || '');
    sources.push({
      id: src.id || `source-${i + 1}`,
      origin: src.origin || 'untrusted content',
      trust,
      text: String(src.text || ''),
      haystack: lower(injection.deob.analysisText),
      injection
    });
  }
  return {
    prepared: true,
    trustedText,
    trustedLower: lower(deobfuscate(trustedText).text),
    sources,
    secrets: [...new Set((context.secrets || []).map(String).filter((s) => s.length >= 8))],
    history: Array.isArray(context.history) ? context.history : []
  };
}

export function traceValue(value, ctx) {
  const v = lower(deobfuscate(value).text).trim();
  const result = { endorsed: false, sources: [] };
  if (!v) return result;
  if (v.length >= 3 && ctx.trustedLower.includes(v)) result.endorsed = true;
  for (const src of ctx.sources) {
    if (v.length >= 6 && src.haystack.includes(v)) {
      result.sources.push({ id: src.id, origin: src.origin, how: 'verbatim', excerpt: v.slice(0, 80) });
      continue;
    }
    const run = longestCommonString(v, src.haystack);
    if (run.trim().length >= 20 && !ctx.trustedLower.includes(run.trim())) {
      result.sources.push({ id: src.id, origin: src.origin, how: 'partial copy', excerpt: run.trim().slice(0, 80) });
    }
  }
  return result;
}

function entityEndorsed(entity, ctx) {
  const e = lower(entity).trim();
  if (!e) return false;
  if (ctx.trustedLower.includes(e)) return true;
  const digits = e.replace(/\D/g, '');
  if (digits.length >= 6 && ctx.trustedLower.replace(/\D/g, '').includes(digits)) return true;
  return false;
}

// ---------- secrets learned from tool results ----------

const SECRET_KEY = /(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|session|cookie|dsn|database_url)/i;

export function extractSecrets(text) {
  const found = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*["']?([^"'\s#]+)["']?/);
    if (!m) continue;
    const [, key, value] = m;
    if (value.length < 8) continue;
    if (SECRET_KEY.test(key) || (value.length >= 20 && shannonEntropy(value) >= 3.5)) found.push(value);
  }
  for (const m of String(text ?? '').matchAll(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g)) found.push(m[0]);
  return [...new Set(found)];
}

// After a tool runs, its output becomes context: secrets from sensitive reads are
// remembered, and anything fetched from the outside becomes untrusted content.
export function learnFromResult(call, result, context, policy = PRESETS.balanced) {
  const next = {
    trusted: [...(context.trusted || [])],
    untrusted: [...(context.untrusted || [])],
    secrets: [...(context.secrets || [])],
    history: [...(context.history || []), { tool: call.tool }]
  };
  const text = typeof result === 'string' ? result : JSON.stringify(result ?? '');
  const spec = TOOL_CATALOG[call.tool];
  if (!spec) return next;
  if (spec.effect === 'fs-read') {
    const resolved = canonicalizePath(call.args?.path, policy).resolved;
    const sensitive = SENSITIVE_PATTERNS.some(([p]) => p.test(resolved));
    if (sensitive) next.secrets.push(...extractSecrets(text));
    next.untrusted.push({ id: `result-${next.history.length}`, origin: `file ${resolved}`, trust: 'internal', text });
  } else if (spec.effect === 'egress-read') {
    next.untrusted.push({ id: `result-${next.history.length}`, origin: `web ${call.args?.url || call.args?.query || ''}`.trim(), trust: 'untrusted', text });
  } else if (text) {
    next.untrusted.push({ id: `result-${next.history.length}`, origin: `${call.tool} output`, trust: 'untrusted', text });
  }
  return next;
}

// ---------- per-argument analyzers ----------

function urlFindings(url, ctx, policy, writeClass) {
  const res = analyzeUrl(url, { egressAllow: policy.egressAllow, knownSecrets: ctx.secrets, protectedBrands: policy.protectedBrands });
  return res.findings.map((f) => (writeClass && f.rule === 'egressNotAllowed' ? { ...f, rule: 'egressWriteNotAllowed', message: f.message.replace('not on the egress allowlist', 'not on the egress allowlist, and this call sends data') } : f));
}

function bodySecretFindings(body, ctx) {
  const out = [];
  const text = String(body ?? '');
  const deob = deobfuscate(text);
  const hay = `${text}\n${deob.analysisText}`;
  for (const secret of ctx.secrets) {
    const secretBytes = [...new TextEncoder().encode(secret)];
    const hex = secretBytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    const b64 = btoa(String.fromCharCode(...secretBytes)).replace(/=+$/, '');
    if (hay.includes(secret) || lower(hay).includes(hex.slice(0, 24)) || hay.includes(b64.slice(0, 16))) {
      out.push({ rule: 'secretExfil', severity: 'critical', message: 'Payload contains a secret read earlier in this session.' });
      return out;
    }
  }
  if (extractSecrets(deob.analysisText).length || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(hay)) {
    out.push({ rule: 'secretExfil', severity: 'critical', message: 'Payload contains credential assignments (KEY=value) or a private key.' });
  }
  return out;
}

function markdownFindings(markdown, ctx, policy) {
  const out = [];
  const text = deobfuscate(markdown).text;
  const urls = [];
  for (const m of text.matchAll(/!\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)/g)) urls.push(m[1]);
  for (const m of text.matchAll(/<img\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) urls.push(m[1]);
  for (const m of text.matchAll(/^\s*\[[^\]]+\]:\s*(\S+)/gm)) urls.push(m[1]);
  for (const url of urls) {
    const res = analyzeUrl(url, { egressAllow: policy.egressAllow, knownSecrets: ctx.secrets, protectedBrands: policy.protectedBrands });
    const external = res.ok && res.host && !policy.egressAllow.some((d) => hostMatches(res.host, d));
    for (const f of res.findings) if (f.rule !== 'egressNotAllowed') out.push(f);
    if (external) {
      const carries = /[?#]./.test(url) || res.findings.some((f) => f.rule === 'secretExfil' || f.rule === 'dnsExfil');
      out.push(carries
        ? { rule: 'markdownBeacon', severity: 'critical', message: `Image from ${res.host} fires a request carrying data the moment it renders.` }
        : { rule: 'egressNotAllowed', severity: 'medium', message: `Image loads from ${res.host}, outside the allowlist.` });
    }
  }
  return out;
}

function shellFindings(cmd, ctx) {
  const analysis = analyzeShell(cmd);
  const out = [...analysis.findings];
  for (const c of analysis.commands) {
    for (const arg of c.args) for (const url of extractUrls(arg)) out.push({ rule: '__url', url });
    if (c.name === 'cat' || c.name === 'cp' || c.name === 'tar' || c.name === 'zip' || c.name === 'scp') {
      for (const arg of c.args) if (!arg.startsWith('-')) out.push({ rule: '__path', path: arg });
    }
  }
  // Command injection: operators that appear inside text copied from untrusted content.
  const metaFeatures = analysis.features.filter((f) => ['chain', 'pipe', 'substitution', 'background'].includes(f));
  if (metaFeatures.length) {
    const cmdLower = lower(deobfuscate(cmd).text);
    for (const src of ctx.sources) {
      const run = longestCommonString(cmdLower, src.haystack);
      if (run.length >= 6 && /[;|&`]|\$\(|\n/.test(run) && !ctx.trustedLower.includes(run)) {
        out.push({ rule: 'shellMetaFromUntrusted', severity: 'critical', message: `Shell operators came from ${src.origin}: "${run.trim().slice(0, 60)}".` });
        break;
      }
    }
  }
  return { analysis, findings: out };
}

function argFindings(tool, spec, args, ctx, policy) {
  const findings = [];
  const details = {};
  for (const [name, kind] of Object.entries(spec.args)) {
    const value = args[name];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value !== 'string' && !(kind === 'amount' && typeof value === 'number')) {
      findings.push({ rule: 'badArgs', severity: 'high', message: `${name} must be a string.`, arg: name });
      continue;
    }
    const text = String(value);
    if (kind === 'path' || kind === 'path-write') {
      const res = analyzePath(text, { workspaceRoot: policy.workspaceRoot, homeDir: policy.homeDir, mode: kind === 'path-write' ? 'write' : 'read' });
      details[name] = { resolved: res.resolved };
      for (const f of res.findings) findings.push({ ...f, arg: name });
    } else if (kind === 'url') {
      for (const f of urlFindings(text, ctx, policy, spec.effect === 'egress-write')) findings.push({ ...f, arg: name });
    } else if (kind === 'shell') {
      const res = shellFindings(text, ctx);
      details[name] = { commands: res.analysis.commands.map((c) => c.name).filter(Boolean), features: res.analysis.features };
      for (const f of res.findings) {
        if (f.rule === '__url') for (const g of urlFindings(f.url, ctx, policy, false)) findings.push({ ...g, arg: name });
        else if (f.rule === '__path') {
          for (const g of analyzePath(f.path, { workspaceRoot: policy.workspaceRoot, homeDir: policy.homeDir }).findings) findings.push({ ...g, arg: name });
        } else findings.push({ ...f, arg: name });
      }
    } else if (kind === 'markdown') {
      for (const f of markdownFindings(text, ctx, policy)) findings.push({ ...f, arg: name });
    } else if (kind === 'body') {
      if (spec.effect !== 'fs-write') for (const f of bodySecretFindings(text, ctx)) findings.push({ ...f, arg: name });
      for (const url of extractUrls(deobfuscate(text).text)) {
        if (spec.effect === 'fs-write') continue;
        for (const f of urlFindings(url, ctx, policy, false)) if (['ssrf', 'homoglyphHost', 'dnsExfil'].includes(f.rule)) findings.push({ ...f, arg: name });
      }
      if (tool === 'write_file' && (/^#!/.test(text) || /\.(sh|bash|zsh|command)$|\/hooks\//.test(String(args.path || '')))) {
        const script = shellFindings(text, ctx);
        for (const f of script.findings) {
          if (f.rule === '__url') {
            for (const g of urlFindings(f.url, ctx, policy, false)) if (g.rule !== 'egressNotAllowed') findings.push({ ...g, arg: name });
          } else if (f.rule !== '__path' && f.rule !== 'shellMetaFromUntrusted') findings.push({ ...f, arg: name, message: `Script body: ${f.message}` });
        }
      }
      if (tool === 'write_file' && /"(preinstall|install|postinstall|prepare)"\s*:/.test(text)) {
        findings.push({ rule: 'installHook', severity: 'high', message: 'Write adds an npm lifecycle script that runs on install.', arg: name });
      }
    } else if (kind === 'recipient') {
      for (const addr of text.split(/[,;\s]+/).filter(Boolean)) {
        if (!entityEndorsed(addr, ctx)) {
          const domain = addr.split('@')[1] || '';
          const internal = domain && policy.egressAllow.some((d) => hostMatches(domain, d));
          findings.push({ rule: 'unendorsedRecipient', severity: 'high', message: `${addr} was never named by the user${internal ? '' : ' and is outside the organization'}.`, arg: name });
        }
        const domain = addr.split('@')[1];
        if (domain) {
          for (const f of urlFindings(`https://${domain}/`, ctx, policy, false)) if (f.rule === 'homoglyphHost') findings.push({ ...f, arg: name });
        }
      }
    } else if (kind === 'payee') {
      if (!entityEndorsed(text, ctx)) findings.push({ rule: 'unendorsedPayee', severity: 'critical', message: `Account ${text} was never named by the user.`, arg: name });
    }
  }
  return { findings, details };
}

// ---------- the decision function ----------

/**
 * Decides one tool call. Returns { decision, risk, findings, matched, provenance }.
 * Fails closed: any exception becomes a deny.
 */
export function evaluateCall(call, context = {}, policy = PRESETS.balanced) {
  try {
    return evaluateCallUnsafe(call, context, policy);
  } catch (error) {
    return {
      decision: 'deny',
      risk: 100,
      findings: [{ rule: 'guardError', severity: 'critical', message: `Guard error: ${String(error && error.message || error).slice(0, 160)}`, action: 'deny' }],
      matched: [{ rule: 'guardError', action: 'deny' }],
      provenance: {},
      details: {}
    };
  }
}

function evaluateCallUnsafe(call, rawContext, policy) {
  const ctx = rawContext && rawContext.prepared ? rawContext : prepareContext(rawContext || {}, policy);
  const tool = call && typeof call.tool === 'string' ? call.tool : '';
  const spec = TOOL_CATALOG[tool];
  const toolPolicy = policy.tools[tool];
  const findings = [];
  if (!spec || !toolPolicy) {
    findings.push({ rule: 'unknownTool', severity: 'critical', message: `"${tool || '(none)'}" is not an allowed tool.` });
    return finalize(findings, policy, policy.defaultAction === 'allow' ? 'deny' : policy.defaultAction, {}, {});
  }
  const args = call.args;
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    findings.push({ rule: 'badArgs', severity: 'high', message: 'Arguments must be an object.' });
    return finalize(findings, policy, toolPolicy.action, {}, {});
  }
  for (const key of Object.keys(args)) {
    if (!spec.args[key]) findings.push({ rule: 'badArgs', severity: 'high', message: `Unexpected argument "${key}" for ${tool}.`, arg: key });
  }
  for (const { path, value } of collectStrings(args)) {
    if (value.length > toolPolicy.maxArgChars) findings.push({ rule: 'argCap', severity: 'medium', message: `${path} is ${value.length} chars (cap ${toolPolicy.maxArgChars}).`, arg: path });
  }
  const priorCalls = ctx.history.filter((h) => h && h.tool === tool).length;
  if (priorCalls >= toolPolicy.maxCalls) findings.push({ rule: 'rateLimit', severity: 'high', message: `${tool} already ran ${priorCalls} times (cap ${toolPolicy.maxCalls}).` });

  const { findings: argF, details } = argFindings(tool, spec, args, ctx, policy);
  findings.push(...argF);

  // Taint: which argument values were copied from untrusted content?
  const provenance = {};
  for (const name of Object.keys(spec.args)) {
    const value = args[name];
    if (typeof value !== 'string' || !value) continue;
    const trace = traceValue(value, ctx);
    if (trace.sources.length) provenance[name] = trace;
  }
  const taintedArgs = Object.entries(provenance).filter(([, t]) => t.sources.length && !t.endorsed);
  if (spec.privileged && taintedArgs.length) {
    const [arg, t] = taintedArgs[0];
    if (spec.effect === 'exec') {
      findings.push({ rule: 'taintedExec', severity: 'medium', message: `Command text was copied from ${t.sources[0].origin}.`, arg });
    } else {
      findings.push({ rule: 'untrustedToPrivilegedSink', severity: 'high', message: `${arg} carries text from ${t.sources[0].origin} into ${EFFECT_LABELS[spec.effect].toLowerCase()}.`, arg });
    }
  }
  if (spec.privileged) {
    const hot = ctx.sources.filter((s) => s.injection.score >= policy.injectionThreshold);
    if (hot.length) {
      const top = hot.sort((a, b) => b.injection.score - a.injection.score)[0];
      findings.push({ rule: 'injectedContext', severity: 'high', message: `${top.origin} scored ${Math.round(top.injection.score * 100)} for injection (${top.injection.hits.map((h) => h.label).join(', ')}).` });
    }
  }
  return finalize(findings, policy, toolPolicy.action, provenance, details, spec);
}

function finalize(rawFindings, policy, baseAction, provenance, details, spec) {
  const seen = new Set();
  const findings = [];
  for (const f of rawFindings) {
    const key = `${f.rule}|${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const action = policy.rules[f.rule] || 'deny';
    findings.push({ ...f, severity: f.severity || (RULES[f.rule] ? RULES[f.rule][0] : 'high'), action });
  }
  const matched = [];
  if (spec) matched.push({ rule: 'tool', action: baseAction });
  for (const f of findings) matched.push({ rule: f.rule, action: f.action });
  const decision = strictestAction([spec ? baseAction : 'allow', ...findings.map((f) => f.action)]);
  const risk = Math.round(combineWeights(findings.map((f) => SEVERITY_WEIGHT[f.severity] ?? 0.5)) * 100);
  findings.sort((a, b) => actionRank(b.action) - actionRank(a.action) || (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0));
  return { decision, risk, findings, matched, provenance, details, effect: spec ? spec.effect : 'unknown' };
}
