// The policy evaluator. evaluateCall() is the single decision function used by
// the workbench AND by the exported shieldgraph-guard.mjs, so both always agree.
import { ACTIONS, actionRank, strictestAction, collectStrings, combineWeights, longestCommonString, shannonEntropy, WORK_LIMITS, hasOwn, createWorkBudget, exceedBudget, reservePairwiseComparison } from './util.mjs';
import { deobfuscate } from './deobfuscate.mjs';
import { analyzeUrl, extractUrls, hostMatches } from './netguard.mjs';
import { analyzePath, canonicalizePath, SENSITIVE_PATTERNS } from './pathguard.mjs';
import { analyzeShell } from './shell.mjs';
import { scoreInjection } from './injection.mjs';

const MAP_ENTRIES = Map.prototype.entries;
const MAP_ITERATOR_NEXT = Object.getPrototypeOf(MAP_ENTRIES.call(new Map())).next;

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
  send_email: { effect: 'comms', privileged: true, args: { to: 'recipient', subject: 'text', body: 'body' }, optional: ['subject'] },
  transfer_funds: { effect: 'finance', privileged: true, args: { to_account: 'payee', amount: 'amount', memo: 'text' }, optional: ['memo'] },
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
  budgetExceeded: ['critical', 'Input or retained context exceeds the guard work budget.'],
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
  scriptSpawn: ['high', 'Inline script spawns processes or opens connections.'],
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
const FAIL_CLOSED_RULES = new Set(['unknownTool', 'guardError', 'badArgs', 'budgetExceeded']);

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

/** Appends one call to retained history without letting the retained log grow past 256 entries. */
export function appendHistoryEntry(context, tool) {
  const base = context && typeof context === 'object' ? context : {};
  const history = Array.isArray(base.history) ? base.history : [];
  return { ...base, history: [...history, { tool }].slice(-256) };
}

export function recordQuotaCall(quotaCounts, tool, policy) {
  const tools = policy && policy.tools && typeof policy.tools === 'object' ? policy.tools : {};
  if (!(quotaCounts instanceof Map) || typeof tool !== 'string' || !hasOwn(tools, tool)) return false;
  quotaCounts.set(tool, (quotaCounts.get(tool) || 0) + 1);
  return true;
}

const INPUT_CLONE_LIMITS = Object.freeze({
  maxKeys: WORK_LIMITS.maxObjectKeys,
  maxStrings: WORK_LIMITS.maxCollectedStrings,
  maxDepth: WORK_LIMITS.maxCollectDepth,
  maxStringChars: WORK_LIMITS.maxArgumentChars,
  maxStringBytes: WORK_LIMITS.maxArgumentBytes,
  maxTotalChars: WORK_LIMITS.maxCallChars,
  maxTotalBytes: WORK_LIMITS.maxCallBytes
});

const GENERATED_CLONE_LIMITS = Object.freeze({
  maxKeys: 131072,
  maxStrings: 131072,
  maxDepth: 24,
  maxStringChars: 65536,
  maxStringBytes: 262144,
  maxTotalChars: 1048576,
  maxTotalBytes: 4194304
});

function cloneBudgetFailure(message) {
  const error = new Error(message);
  error.name = 'ShieldGraphCloneBudget';
  error.rule = 'budgetExceeded';
  return error;
}

function cloneFail(message) {
  throw cloneBudgetFailure(message);
}

function utf8ByteLength(text, stopAt) {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 128) bytes += 1;
    else if (code < 2048) bytes += 2;
    else if (code >= 55296 && code <= 56319 && i + 1 < text.length && text.charCodeAt(i + 1) >= 56320 && text.charCodeAt(i + 1) <= 57343) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
    if (bytes > stopAt) return bytes;
  }
  return bytes;
}

function chargeCloneString(text, state, label, scalar) {
  const limits = state.limits;
  if (text.length > limits.maxStringChars) {
    cloneFail(label + ' is ' + text.length + ' chars, above the hard argument cap of ' + limits.maxStringChars + '.');
  }
  if (state.chars + text.length > limits.maxTotalChars) {
    cloneFail('Tool call structure carries more than ' + limits.maxTotalChars + ' string chars.');
  }
  const byteRoom = Math.min(limits.maxStringBytes, limits.maxTotalBytes - state.bytes);
  const bytes = utf8ByteLength(text, byteRoom);
  if (bytes > limits.maxStringBytes) {
    cloneFail(label + ' is ' + bytes + ' bytes, above the hard argument cap of ' + limits.maxStringBytes + '.');
  }
  if (state.bytes + bytes > limits.maxTotalBytes) {
    cloneFail('Tool call structure carries more than ' + limits.maxTotalBytes + ' string bytes.');
  }
  state.chars += text.length;
  state.bytes += bytes;
  if (scalar) {
    state.strings += 1;
    if (state.strings > limits.maxStrings) cloneFail('Tool call structure has more than ' + limits.maxStrings + ' scalar values.');
  }
}

function countCloneKey(state) {
  state.keys += 1;
  if (state.keys > state.limits.maxKeys) cloneFail('Tool call structure has more than ' + state.limits.maxKeys + ' enumerable keys.');
}

function cloneKey(input, key, copy, state, depth) {
  if (typeof key === 'string') chargeCloneString(key, state, 'Object key', false);
  const value = cloneValue(input[key], state, depth + 1);
  Object.defineProperty(copy, key, { value, enumerable: true, writable: false, configurable: false });
}

function cloneValue(value, state, depth) {
  if (typeof value === 'string') {
    chargeCloneString(value, state, 'Argument string', true);
    return value;
  }
  if (!value || typeof value !== 'object') return value;
  if (depth > state.limits.maxDepth) cloneFail('Tool call structure is nested deeper than ' + state.limits.maxDepth + ' levels.');
  if (state.active.has(value)) cloneFail('Tool call structure contains a cycle.');
  state.active.add(value);
  const copy = Array.isArray(value) ? [] : Object.create(null);
  try {
    for (const key in value) {
      countCloneKey(state);
      if (Object.hasOwn(value, key)) cloneKey(value, key, copy, state, depth);
    }
    for (const key of Object.getOwnPropertySymbols(value)) {
      countCloneKey(state);
      if (Object.prototype.propertyIsEnumerable.call(value, key)) cloneKey(value, key, copy, state, depth);
    }
  } finally {
    state.active.delete(value);
  }
  return Object.freeze(copy);
}

function cloneWithLimits(value, limits) {
  const state = { limits, keys: 0, strings: 0, chars: 0, bytes: 0, active: new Set() };
  return cloneValue(value, state, -1);
}

function cloneFrozen(value) {
  return cloneWithLimits(value, INPUT_CLONE_LIMITS);
}

function cloneGeneratedFrozen(value) {
  return cloneWithLimits(value, GENERATED_CLONE_LIMITS);
}

function frozenEmptyObject() {
  return Object.freeze(Object.create(null));
}

function budgetVerdict(message) {
  const finding = Object.freeze({ rule: 'budgetExceeded', severity: 'critical', message, action: 'deny' });
  const matched = Object.freeze({ rule: 'budgetExceeded', action: 'deny' });
  return Object.freeze({
    decision: 'deny',
    risk: 100,
    findings: Object.freeze([finding]),
    matched: Object.freeze([matched]),
    provenance: frozenEmptyObject(),
    details: frozenEmptyObject(),
    effect: 'unknown'
  });
}

function fallbackCall(input) {
  const tool = input && typeof input === 'object' && typeof input.tool === 'string' ? input.tool.slice(0, 160) : '';
  const call = Object.create(null);
  Object.defineProperty(call, 'tool', { value: tool, enumerable: true, writable: false, configurable: false });
  Object.defineProperty(call, 'args', { value: frozenEmptyObject(), enumerable: true, writable: false, configurable: false });
  return Object.freeze(call);
}

function snapshotCall(input) {
  try {
    return { call: cloneFrozen(input), verdict: null };
  } catch (error) {
    if (!error || error.rule !== 'budgetExceeded') throw error;
    return { call: fallbackCall(input), verdict: budgetVerdict(error.message) };
  }
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
      if (!hasOwn(TOOL_CATALOG, name)) {
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
      if (!hasOwn(RULES, id)) errors.push(`rules.${id} is not a known rule.`);
      else if (!ACTIONS.includes(action)) errors.push(`rules.${id} must be one of ${ACTIONS.join(', ')}.`);
      else policy.rules[id] = action;
    }
  }
  for (const id of RULE_IDS) if (!policy.rules[id]) policy.rules[id] = 'deny';
  for (const id of FAIL_CLOSED_RULES) policy.rules[id] = 'deny';
  return { ok: errors.length === 0, errors, policy: errors.length ? null : policy };
}

// ---------- provenance ----------

function lower(s) {
  return String(s ?? '').toLowerCase();
}

const SOURCE_SCAN_CACHE = new WeakMap();

function scanUntrustedSource(key, text) {
  const canCache = key && (typeof key === 'object' || typeof key === 'function');
  if (canCache) {
    const cached = SOURCE_SCAN_CACHE.get(key);
    if (cached && cached.text === text) return cached.scan;
  }
  const injection = scoreInjection(text);
  const scan = { injection, haystack: lower(injection.deob.analysisText) };
  if (canCache) SOURCE_SCAN_CACHE.set(key, { text, scan });
  return scan;
}

const PROTO_KEY_CONTEXT_MESSAGE = 'Context object contains an own __proto__ key.';
const CONTEXT_SNAPSHOT_BUDGET_MESSAGE = `Context snapshot inspects more than ${WORK_LIMITS.maxContextKeys} properties or elements.`;
const CONTEXT_SNAPSHOT_DEPTH_MESSAGE = 'Context snapshot is cyclic or nested too deeply.';
const CONTEXT_UNSUPPORTED_MESSAGE = 'Context object contains an unsupported function or class instance.';
const PREPARED_POLICY_MISMATCH_MESSAGE = 'Prepared context was created under a different policy.';

function immutableQuotaCounts(counts) {
  if (!counts) return null;
  const api = Object.create(null);
  for (const tool of Object.getOwnPropertyNames(counts)) {
    Object.defineProperty(api, tool, { value: counts[tool], enumerable: true, writable: false, configurable: false });
  }
  return Object.freeze(api);
}

function normalizeQuotaCounts(raw, policy) {
  if (raw === undefined || raw === null) return null;
  const entries = [];
  if (Array.isArray(raw)) {
    for (let i = 0; i < raw.length; i += 1) {
      const entry = raw[i];
      if (Array.isArray(entry)) entries.push([entry[0], entry[1]]);
    }
  } else if (raw instanceof Map) {
    const iterator = MAP_ENTRIES.call(raw);
    while (true) {
      const step = MAP_ITERATOR_NEXT.call(iterator);
      if (step.done) break;
      entries.push([step.value[0], step.value[1]]);
    }
  } else if (raw && typeof raw === 'object') {
    for (const key of Object.getOwnPropertyNames(raw)) entries.push([key, raw[key]]);
  }
  const configuredTools = policy && policy.tools && typeof policy.tools === 'object' ? policy.tools : {};
  const totals = Object.create(null);
  for (const entry of entries) {
    const tool = entry[0];
    const value = entry[1];
    const count = Number(value);
    if (typeof tool !== 'string' || !hasOwn(configuredTools, tool) || !Number.isFinite(count) || count <= 0) continue;
    totals[tool] = (totals[tool] || 0) + Math.floor(count);
  }
  return immutableQuotaCounts(totals);
}

function noteContextSnapshot(state, message) {
  if (!state.errors.includes(message)) state.errors.push(message);
}

function countContextInspection(state) {
  if (state.stop) return false;
  state.inspected += 1;
  if (state.inspected > WORK_LIMITS.maxContextKeys) {
    noteContextSnapshot(state, CONTEXT_SNAPSHOT_BUDGET_MESSAGE);
    state.stop = true;
    return false;
  }
  return true;
}

function snapshotArrayValue(value, state, depth) {
  const copy = [];
  try {
    if (countContextInspection(state)) {
      const length = value.length;
      for (let i = 0; i < length; i += 1) {
        if (!countContextInspection(state)) break;
        copy[i] = snapshotContextValue(value[i], state, depth + 1);
      }
    }
    if (countContextInspection(state) && hasOwn(value, '__proto__') && countContextInspection(state)) {
      Object.defineProperty(copy, '__proto__', {
        value: snapshotContextValue(value.__proto__, state, depth + 1),
        enumerable: true,
        writable: false,
        configurable: false
      });
    }
  } finally {
    state.active.delete(value);
  }
  return Object.freeze(copy);
}

function snapshotMapValue(value, state, depth) {
  const copy = [];
  try {
    const iterator = MAP_ENTRIES.call(value);
    while (!state.stop) {
      const step = MAP_ITERATOR_NEXT.call(iterator);
      if (step.done) break;
      if (!countContextInspection(state)) break;
      if (!countContextInspection(state)) break;
      if (!countContextInspection(state)) break;
      const entry = step.value;
      copy.push(Object.freeze([
        snapshotContextValue(entry[0], state, depth + 1),
        snapshotContextValue(entry[1], state, depth + 1)
      ]));
    }
  } finally {
    state.active.delete(value);
  }
  return Object.freeze(copy);
}

function snapshotPlainObjectValue(value, state, depth) {
  const copy = Object.create(null);
  try {
    for (const key of Object.getOwnPropertyNames(value)) {
      if (!countContextInspection(state)) break;
      Object.defineProperty(copy, key, {
        value: snapshotContextValue(value[key], state, depth + 1),
        enumerable: true,
        writable: false,
        configurable: false
      });
    }
  } finally {
    state.active.delete(value);
  }
  return Object.freeze(copy);
}

function snapshotContextValue(value, state, depth) {
  if (state.stop) return undefined;
  if (typeof value === 'function') {
    noteContextSnapshot(state, CONTEXT_UNSUPPORTED_MESSAGE);
    return undefined;
  }
  if (!value || typeof value !== 'object') return value;
  if (!countContextInspection(state)) return undefined;
  if (depth >= 32 || state.active.has(value)) {
    noteContextSnapshot(state, CONTEXT_SNAPSHOT_DEPTH_MESSAGE);
    state.stop = true;
    return undefined;
  }
  state.active.add(value);
  let copy;
  if (Array.isArray(value)) copy = snapshotArrayValue(value, state, depth);
  else if (value instanceof Map) copy = snapshotMapValue(value, state, depth);
  else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype === Object.prototype || prototype === null) copy = snapshotPlainObjectValue(value, state, depth);
    else {
      state.active.delete(value);
      noteContextSnapshot(state, CONTEXT_UNSUPPORTED_MESSAGE);
      return undefined;
    }
  }
  state.originals.set(copy, value);
  return copy;
}

function snapshotContextInput(context) {
  const state = { inspected: 0, active: new Set(), originals: new WeakMap(), errors: [], stop: false };
  const value = snapshotContextValue(context, state, 0);
  return { value, originals: state.originals, errors: state.errors };
}

function scanSnapshottedContext(value, state, depth = 0) {
  if (!value || typeof value !== 'object') return;
  if (depth >= 32 || state.active.has(value)) return;
  state.active.add(value);
  try {
    if (hasOwn(value, '__proto__')) state.hasProtoKey = true;
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) scanSnapshottedContext(value[i], state, depth + 1);
    } else {
      for (const key of Object.getOwnPropertyNames(value)) scanSnapshottedContext(value[key], state, depth + 1);
    }
  } finally {
    state.active.delete(value);
  }
}

function validateContextSnapshot(value) {
  const state = { hasProtoKey: false, active: new Set() };
  scanSnapshottedContext(value, state);
  return state;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function') || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && hasOwn(descriptor, 'value')) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}

function stablePolicyDatum(value, active = new Set()) {
  if (Array.isArray(value)) {
    if (active.has(value)) throw new Error('Policy contains a cycle.');
    active.add(value);
    try {
      const out = [];
      for (let i = 0; i < value.length; i += 1) out[i] = stablePolicyDatum(value[i], active);
      return out;
    } finally {
      active.delete(value);
    }
  }
  if (value && typeof value === 'object') {
    if (active.has(value)) throw new Error('Policy contains a cycle.');
    active.add(value);
    try {
      const out = Object.create(null);
      for (const key of Object.getOwnPropertyNames(value).sort()) {
        const item = value[key];
        if (item === undefined || typeof item === 'function') continue;
        out[key] = stablePolicyDatum(item, active);
      }
      return out;
    } finally {
      active.delete(value);
    }
  }
  return value;
}

function policyKey(policy) {
  return JSON.stringify(stablePolicyDatum(policy));
}

const PREPARED_CONTEXTS = new WeakMap();

/**
 * Prepares a context once so many calls can be checked cheaply.
 * context = { trusted: string[], untrusted: [{id, origin, text, trust?}], secrets: string[], history: [{tool}], quotaCounts?: Map|object }
 * Retained input is capped before any detector runs. Oversized context is not
 * silently trusted; the evaluator turns the budget marker into a fail-closed finding.
 */
export function prepareContext(context = {}, policy = PRESETS.balanced) {
  const budgetExceeded = [];
  const note = (reason) => { if (!budgetExceeded.includes(reason)) budgetExceeded.push(reason); };

  const snapshot = snapshotContextInput(context);
  for (const reason of snapshot.errors) note(reason);
  const input = snapshot.value && typeof snapshot.value === 'object' ? snapshot.value : Object.create(null);
  const validation = validateContextSnapshot(input);
  if (validation.hasProtoKey) note(PROTO_KEY_CONTEXT_MESSAGE);
  const rejectContext = snapshot.errors.length > 0 || validation.hasProtoKey;

  const rawHistory = rejectContext || !Array.isArray(input.history) ? [] : input.history;
  const historyOverCap = rawHistory.length > 256;
  if (historyOverCap) note('Retained tool-call history exceeds 256 entries.');
  const history = [];
  if (!historyOverCap && !rejectContext) {
    const start = Math.max(0, rawHistory.length - 256);
    for (let i = start; i < rawHistory.length; i += 1) history.push(rawHistory[i]);
  }
  const quotaCounts = rejectContext ? null : normalizeQuotaCounts(input.quotaCounts, policy);

  let contextItems = 0;
  let retainedChars = 0;
  const takeContextItem = () => {
    if (contextItems >= WORK_LIMITS.maxContextItems) {
      note(`Retained context has more than ${WORK_LIMITS.maxContextItems} items.`);
      return false;
    }
    contextItems += 1;
    return true;
  };
  const retain = (value, kind) => {
    const original = String(value ?? '');
    const room = Math.max(0, WORK_LIMITS.maxContextChars - retainedChars);
    const allowed = Math.min(WORK_LIMITS.maxSourceChars, room);
    let text = original;
    let truncated = false;
    if (text.length > allowed) {
      truncated = true;
      text = text.slice(0, allowed);
      note(`Retained ${kind} exceeds the context size budget (${WORK_LIMITS.maxContextChars} chars total, ${WORK_LIMITS.maxSourceChars} chars each).`);
    }
    retainedChars += text.length;
    return { text, truncated, originalLength: original.length };
  };

  const trustedParts = [];
  const rawTrusted = historyOverCap || rejectContext || !Array.isArray(input.trusted) ? [] : input.trusted;
  for (let i = 0; i < rawTrusted.length; i += 1) {
    if (!takeContextItem()) break;
    trustedParts.push(retain(rawTrusted[i], 'trusted context').text);
  }
  const trustedText = trustedParts.join('\n');

  const sources = [];
  const rawSources = historyOverCap || rejectContext || !Array.isArray(input.untrusted) ? [] : input.untrusted;
  for (let i = 0; i < rawSources.length; i += 1) {
    if (!takeContextItem()) break;
    const sourceInput = rawSources[i];
    const src = sourceInput && typeof sourceInput === 'object' ? sourceInput : { text: sourceInput };
    const trust = src.trust === 'internal' ? 'internal' : 'untrusted';
    if (trust === 'internal' && policy.trustInternal) continue;
    const held = retain(src.text || '', 'untrusted context');
    const scanKey = sourceInput && typeof sourceInput === 'object' ? snapshot.originals.get(sourceInput) || sourceInput : sourceInput;
    const scan = scanUntrustedSource(scanKey, held.text);
    sources.push({
      id: src.id || `source-${i + 1}`,
      origin: src.origin || 'untrusted content',
      trust,
      text: held.text,
      truncated: held.truncated,
      sourceChars: held.originalLength,
      haystack: scan.haystack,
      injection: scan.injection
    });
  }

  const secrets = [];
  const seenSecrets = new Set();
  const rawSecrets = historyOverCap || rejectContext || !Array.isArray(input.secrets) ? [] : input.secrets;
  for (let i = 0; i < rawSecrets.length; i += 1) {
    if (!takeContextItem()) break;
    const value = String(rawSecrets[i]);
    if (value.length < 8 || seenSecrets.has(value)) continue;
    seenSecrets.add(value);
    const held = retain(value, 'secret context');
    if (held.text.length >= 8) secrets.push(held.text);
  }

  const prepared = {
    trustedText,
    trustedLower: lower(deobfuscate(trustedText).text),
    trustedPartsLower: trustedParts.map((part) => lower(deobfuscate(part).text)),
    sources,
    secrets,
    history,
    quotaCounts,
    budgetExceeded
  };
  deepFreeze(prepared);
  PREPARED_CONTEXTS.set(prepared, policyKey(policy));
  return prepared;
}

function rejectedPreparedContext(policy, key) {
  const prepared = {
    trustedText: '',
    trustedLower: '',
    trustedPartsLower: [],
    sources: [],
    secrets: [],
    history: [],
    quotaCounts: null,
    budgetExceeded: [PREPARED_POLICY_MISMATCH_MESSAGE]
  };
  deepFreeze(prepared);
  PREPARED_CONTEXTS.set(prepared, key || policyKey(policy));
  return prepared;
}

export function traceValue(value, ctx, work = null) {
  const v = lower(deobfuscate(value).text).trim();
  const result = { endorsed: false, sources: [], budgetLimited: false };
  if (!v) return result;
  if (v.length >= 3 && containsToken(ctx.trustedLower, v)) result.endorsed = true;
  for (const src of ctx.sources) {
    if (!reservePairwiseComparison(work, v, src.haystack)) {
      result.budgetLimited = true;
      continue;
    }
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

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// True when needle appears in hay as a whole token, not inside a longer word,
// address or number (so "a@x.example" is not endorsed by "ana@x.example").
export function containsToken(hay, needle) {
  const n = String(needle).trim();
  if (!n) return false;
  return new RegExp(`(^|[^\\w@.+-])${escapeRegExp(n)}($|[^\\w@+-]|\\.(?!\\w))`, 'i').test(hay);
}

function accountTokens(text) {
  return (String(text).match(/\d[\d\s-]{3,}\d/g) || []).map((t) => t.replace(/\D/g, '')).filter((d) => d.length >= 6);
}

function entityEndorsed(entity, ctx) {
  const e = lower(entity).trim();
  if (!e) return false;
  if (containsToken(ctx.trustedLower, e)) return true;
  const digits = e.replace(/\D/g, '');
  if (digits.length >= 6 && digits.length === e.replace(/[\s-]/g, '').length) {
    return accountTokens(ctx.trustedLower).includes(digits);
  }
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
  const base = context && typeof context === 'object' ? context : {};
  const list = (value) => Array.isArray(value) ? [...value] : [];
  const next = appendHistoryEntry({
    ...base,
    trusted: list(base.trusted),
    untrusted: list(base.untrusted),
    secrets: list(base.secrets)
  }, call.tool);
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

const SHELL_OPERATOR_PATTERN = /[;|&`]|\$\(|\n/;
const MIN_OPERATOR_WITNESS = 6;

function shellOperatorWitness(text, haystack, trustedPartsLower) {
  const x = String(text).slice(0, 4000);
  const y = String(haystack).slice(0, 4000);
  if (x.length < MIN_OPERATOR_WITNESS || y.length < MIN_OPERATOR_WITNESS) return null;
  const positions = new Map();
  for (let j = 0; j + MIN_OPERATOR_WITNESS <= y.length; j += 1) {
    const key = y.slice(j, j + MIN_OPERATOR_WITNESS);
    if (!positions.has(key)) positions.set(key, []);
    positions.get(key).push(j);
  }
  for (let i = 0; i + MIN_OPERATOR_WITNESS <= x.length; i += 1) {
    const witness = x.slice(i, i + MIN_OPERATOR_WITNESS);
    const operator = witness.match(SHELL_OPERATOR_PATTERN);
    if (!operator) continue;
    const occurrences = positions.get(witness);
    if (!occurrences) continue;
    for (const yFirst of occurrences) {
      let start = i;
      let end = i + MIN_OPERATOR_WITNESS;
      let yStart = yFirst;
      let yEnd = yFirst + MIN_OPERATOR_WITNESS;
      while (start > 0 && yStart > 0 && x[start - 1] === y[yStart - 1]) {
        start -= 1;
        yStart -= 1;
      }
      while (end < x.length && yEnd < y.length && x[end] === y[yEnd]) {
        end += 1;
        yEnd += 1;
      }
      const run = x.slice(start, end);
      if ((Array.isArray(trustedPartsLower) ? trustedPartsLower : []).some((part) => part.includes(run))) continue;
      return {
        text: run,
        operatorIndex: i - start + operator.index,
        operatorLength: operator[0].length
      };
    }
  }
  return null;
}

function shellOperatorExcerpt(run, operatorIndex, operatorLength, max = 60) {
  const text = String(run);
  if (text.length <= max) return text;
  const operatorMiddle = operatorIndex + operatorLength / 2;
  let start = Math.max(0, Math.floor(operatorMiddle - max / 2));
  if (start + max > text.length) start = text.length - max;
  if (start > operatorIndex) start = operatorIndex;
  const end = Math.min(text.length, start + max);
  return text.slice(start, end);
}

function shellFindings(cmd, ctx, work = null) {
  const analysis = analyzeShell(cmd);
  const out = [...analysis.findings];
  for (const c of analysis.commands) {
    for (const arg of c.args) for (const url of extractUrls(arg)) out.push({ rule: '__url', url });
    // Any command can read a file (head, base64, grep, docker --env-file), so every
    // non-flag word and redirect target is checked as a path.
    for (const arg of c.args) {
      const value = arg.startsWith('-') && arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : arg;
      if (!value.startsWith('-') && !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) out.push({ rule: '__path', path: value });
    }
    for (const r of c.redirects) out.push({ rule: '__path', path: r.target });
  }
  // Command injection: operators that appear inside text copied from untrusted content.
  // The outer command and every nested script (sh -c, substitutions) are checked.
  const metaFeatures = analysis.features.filter((f) => ['chain', 'pipe', 'substitution', 'background'].includes(f));
  if (metaFeatures.length) {
    let hit = null;
    for (const text of [cmd, ...(analysis.nested || [])]) {
      const textLower = lower(deobfuscate(text).text);
      let budgetFull = false;
      for (const src of ctx.sources) {
        if (!reservePairwiseComparison(work, textLower, src.haystack)) {
          budgetFull = true;
          break;
        }
        const run = shellOperatorWitness(textLower, src.haystack, ctx.trustedPartsLower);
        if (run) {
          const excerpt = shellOperatorExcerpt(run.text, run.operatorIndex, run.operatorLength);
          hit = { rule: 'shellMetaFromUntrusted', severity: 'critical', message: `Shell operators came from ${src.origin}: "${excerpt}".` };
          break;
        }
      }
      if (hit || budgetFull) break;
    }
    if (hit) out.push(hit);
  }
  return { analysis, findings: out };
}

function argFindings(tool, spec, args, ctx, policy, work = null) {
  const findings = [];
  const details = Object.create(null);
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
      const res = shellFindings(text, ctx, work);
      details[name] = { commands: res.analysis.commands.map((c) => c.name).filter(Boolean), features: res.analysis.features };
      for (const f of res.findings) {
        if (f.rule === '__url') for (const g of urlFindings(f.url, ctx, policy, false)) findings.push({ ...g, arg: name });
        else if (f.rule === '__path') {
          // Keep only the findings that cannot be ordinary shell use: credential files
          // and traversal hidden with encoding. `cd ..` and `ls /usr/bin` stay quiet.
          const res = analyzePath(f.path, { workspaceRoot: policy.workspaceRoot, homeDir: policy.homeDir });
          for (const g of res.findings) {
            if (g.rule === 'sensitivePath' || (g.rule === 'pathTraversal' && res.encoded)) findings.push({ ...g, arg: name });
          }
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
        const script = shellFindings(text, ctx, work);
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
function guardErrorVerdict(error) {
  let message = 'unreadable guard error';
  try {
    const raw = error && typeof error === 'object' && error.message !== undefined ? error.message : error;
    if (typeof raw === 'string') message = raw;
    else if (raw === null || ['number', 'boolean', 'bigint', 'undefined', 'symbol'].includes(typeof raw)) message = String(raw);
    else message = Object.prototype.toString.call(raw);
  } catch {
    message = 'unreadable guard error';
  }
  return {
    decision: 'deny',
    risk: 100,
    findings: [{ rule: 'guardError', severity: 'critical', message: `Guard error: ${message.slice(0, 160)}`, action: 'deny' }],
    matched: [{ rule: 'guardError', action: 'deny' }],
    provenance: {},
    details: {}
  };
}

export function evaluateCall(call, context = {}, policy = PRESETS.balanced) {
  try {
    const snapshot = snapshotCall(call);
    if (snapshot.verdict) return snapshot.verdict;
    return evaluateCallUnsafe(snapshot.call, context, policy);
  } catch (error) {
    return guardErrorVerdict(error);
  }
}

function budgetFindings(work) {
  return work.exceeded.map((message) => ({ rule: 'budgetExceeded', severity: 'critical', message }));
}

function evaluateCallUnsafe(call, rawContext, policy) {
  const key = policyKey(policy);
  let ctx = null;
  if (rawContext && (typeof rawContext === 'object' || typeof rawContext === 'function')) {
    const preparedKey = PREPARED_CONTEXTS.get(rawContext);
    if (preparedKey !== undefined) ctx = preparedKey === key ? rawContext : rejectedPreparedContext(policy, key);
  }
  if (!ctx) ctx = prepareContext(rawContext || {}, policy);
  const work = createWorkBudget();
  for (const reason of ctx.budgetExceeded || []) exceedBudget(work, reason);
  const tool = call && typeof call.tool === 'string' ? call.tool : '';
  const spec = hasOwn(TOOL_CATALOG, tool) ? TOOL_CATALOG[tool] : null;
  const toolPolicy = hasOwn(policy.tools, tool) ? policy.tools[tool] : null;
  const findings = [];
  if (!spec || !toolPolicy) {
    findings.push({ rule: 'unknownTool', severity: 'critical', message: `"${tool || '(none)'}" is not an allowed tool.` });
    findings.push(...budgetFindings(work));
    return finalize(findings, policy, policy.defaultAction === 'allow' ? 'deny' : policy.defaultAction, {}, {});
  }
  if (work.exceeded.length) {
    findings.push(...budgetFindings(work));
    return finalize(findings, policy, toolPolicy.action, {}, {});
  }
  const args = call.args;
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    findings.push({ rule: 'badArgs', severity: 'high', message: 'Arguments must be an object.' });
    findings.push(...budgetFindings(work));
    return finalize(findings, policy, toolPolicy.action, {}, {});
  }
  for (const key of Object.keys(args)) {
    if (!hasOwn(spec.args, key)) findings.push({ rule: 'badArgs', severity: 'high', message: `Unexpected argument "${key}" for ${tool}.`, arg: key });
  }
  for (const [name, kind] of Object.entries(spec.args)) {
    if (!hasOwn(args, name)) {
      if (!(spec.optional || []).includes(name)) findings.push({ rule: 'badArgs', severity: 'high', message: `${name} is required for ${tool}.`, arg: name });
      continue;
    }
    const value = args[name];
    if (kind === 'amount') {
      if (typeof value !== 'number' || !Number.isFinite(value)) findings.push({ rule: 'badArgs', severity: 'high', message: `${name} must be a finite number.`, arg: name });
    } else if (typeof value !== 'string') {
      findings.push({ rule: 'badArgs', severity: 'high', message: `${name} must be a string.`, arg: name });
    }
  }
  if (findings.some((f) => f.rule === 'badArgs')) {
    findings.push(...budgetFindings(work));
    return finalize(findings, policy, toolPolicy.action, {}, {});
  }

  const collected = collectStrings(args, [], '', work);
  for (const { path, value } of collected) {
    if (value.length > WORK_LIMITS.maxArgumentChars) {
      exceedBudget(work, `${path} is ${value.length} chars, above the hard argument cap of ${WORK_LIMITS.maxArgumentChars}.`);
    } else if (value.length > toolPolicy.maxArgChars) {
      findings.push({ rule: 'argCap', severity: 'medium', message: `${path} is ${value.length} chars (cap ${toolPolicy.maxArgChars}).`, arg: path });
    }
  }
  if (work.exceeded.length) {
    findings.push(...budgetFindings(work));
    return finalize(findings, policy, toolPolicy.action, {}, {});
  }

  const priorCalls = ctx.quotaCounts
    ? (hasOwn(ctx.quotaCounts, tool) ? ctx.quotaCounts[tool] : 0)
    : ctx.history.filter((h) => h && h.tool === tool).length;
  if (priorCalls >= toolPolicy.maxCalls) findings.push({ rule: 'rateLimit', severity: 'high', message: `${tool} already ran ${priorCalls} times (cap ${toolPolicy.maxCalls}).` });

  const { findings: argF, details } = argFindings(tool, spec, args, ctx, policy, work);
  findings.push(...argF);

  // Taint: which argument values were copied from untrusted content?
  const provenance = Object.create(null);
  for (const name of Object.keys(spec.args)) {
    const value = args[name];
    if (typeof value !== 'string' || !value) continue;
    const trace = traceValue(value, ctx, work);
    if (trace.sources.length) provenance[name] = trace;
  }
  findings.push(...budgetFindings(work));
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
  const policyRules = policy && policy.rules && typeof policy.rules === 'object' ? policy.rules : {};
  for (const f of rawFindings) {
    const key = `${f.rule}|${f.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const configured = hasOwn(policyRules, f.rule) ? policyRules[f.rule] : 'deny';
    const action = FAIL_CLOSED_RULES.has(f.rule) || !ACTIONS.includes(configured) ? 'deny' : configured;
    const severity = f.severity || (hasOwn(RULES, f.rule) ? RULES[f.rule][0] : 'high');
    findings.push({ ...f, severity, action });
  }
  const matched = [];
  const safeBase = ACTIONS.includes(baseAction) ? baseAction : 'deny';
  if (spec) matched.push({ rule: 'tool', action: safeBase });
  for (const f of findings) matched.push({ rule: f.rule, action: f.action });
  const decision = strictestAction([spec ? safeBase : 'allow', ...findings.map((f) => f.action)]);
  const risk = Math.round(combineWeights(findings.map((f) => SEVERITY_WEIGHT[f.severity] ?? 0.5)) * 100);
  findings.sort((a, b) => actionRank(b.action) - actionRank(a.action) || (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0));
  return { decision, risk, findings, matched, provenance, details, effect: spec ? spec.effect : 'unknown' };
}
