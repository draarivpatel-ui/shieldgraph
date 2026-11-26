// Compiles a policy into one standalone ESM file, shieldgraph-guard.mjs.
// The guard is built from the exact detector sources the workbench runs, so the
// exported middleware and the on-screen verdicts cannot drift apart.

export const GUARD_MODULES = ['util.mjs', 'deobfuscate.mjs', 'netguard.mjs', 'pathguard.mjs', 'shell.mjs', 'injection.mjs', 'policy.mjs'];

const RELATIVE_IMPORT = /^import\s+\{[^}]*\}\s+from\s+'\.\/[\w-]+\.mjs';[ \t]*\r?\n/gm;

export function stripRelativeImports(source) {
  return String(source).replace(RELATIVE_IMPORT, '');
}

export async function sha256Hex(text) {
  const data = new TextEncoder().encode(String(text));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Stable JSON: keys sorted so the same policy always hashes the same way.
export function stableStringify(value, indent = 2) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object') {
      const out = {};
      for (const key of Object.keys(v).sort()) out[key] = sort(v[key]);
      return out;
    }
    return v;
  };
  return JSON.stringify(sort(value), null, indent);
}

const RUNTIME = `
// ---------------------------------------------------------------------------
// Guard runtime (generated)
// ---------------------------------------------------------------------------

export class ShieldGraphBlocked extends Error {
  constructor(call, verdict) {
    const top = verdict.findings[0];
    super(\`ShieldGraph \${verdict.decision}: \${call && call.tool} (\${top ? top.rule + ': ' + top.message : 'policy'})\`);
    this.name = 'ShieldGraphBlocked';
    this.call = call;
    this.verdict = verdict;
  }
}

/** Checks one tool call against the compiled policy without side effects. */
export function checkToolCall(call, context = {}) {
  const snapshot = snapshotCall(call);
  if (snapshot.verdict) return snapshot.verdict;
  return evaluateCall(snapshot.call, context, SHIELDGRAPH_POLICY);
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

// Verdicts are produced by the bounded evaluator, so their copy budget is
// larger than the input budget but still finite.
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

function frozenVerdict(rawVerdict) {
  try {
    return cloneGeneratedFrozen(rawVerdict);
  } catch {
    return budgetVerdict('Guard verdict exceeds the internal copy budget.');
  }
}

function quotaWithReservations(quotaCounts, reservations) {
  const merged = new Map(quotaCounts);
  for (const [tool, count] of reservations) merged.set(tool, (merged.get(tool) || 0) + count);
  return merged;
}

/**
 * Wraps an agent's tool executor. Feed it the user's own words with addTrusted,
 * anything fetched or received with addUntrusted, then route every tool call
 * through run(). Denied calls throw; approval calls ask options.approve.
 */
export function createGuard(options = {}) {
  let context = { trusted: [], untrusted: [], secrets: [], history: [] };
  const log = [];
  const quotaCounts = new Map();
  const reservations = new Map();
  const reserve = (tool) => {
    reservations.set(tool, (reservations.get(tool) || 0) + 1);
    let held = true;
    return () => {
      if (!held) return;
      held = false;
      const next = (reservations.get(tool) || 1) - 1;
      if (next > 0) reservations.set(tool, next);
      else reservations.delete(tool);
    };
  };
  const quotaContext = () => ({ ...context, quotaCounts: quotaWithReservations(quotaCounts, reservations) });
  const guard = {
    addTrusted(text) {
      context = { ...context, trusted: [...context.trusted, String(text)] };
    },
    addUntrusted(text, origin = 'untrusted content', trust = 'untrusted') {
      context = { ...context, untrusted: [...context.untrusted, { id: 'u' + (context.untrusted.length + 1), origin, trust, text: String(text) }] };
    },
    addSecret(value) {
      context = { ...context, secrets: [...context.secrets, String(value)] };
    },
    check(call) {
      return checkToolCall(call, quotaContext());
    },
    async run(input, execute) {
      const snapshot = snapshotCall(input);
      const call = snapshot.call;
      const verdict = snapshot.verdict || frozenVerdict(evaluateCall(call, quotaContext(), SHIELDGRAPH_POLICY));
      const decision = verdict.decision;
      log.push({ tool: call && call.tool, decision, risk: verdict.risk, rules: verdict.findings.map((f) => f.rule) });
      let release = null;
      if (decision !== 'deny') release = reserve(call && call.tool);
      let quotaCommitted = false;
      const commitQuota = () => {
        if (quotaCommitted) return;
        quotaCommitted = true;
        const tool = call && typeof call.tool === 'string' ? call.tool : '';
        quotaCounts.set(tool, (quotaCounts.get(tool) || 0) + 1);
      };
      try {
        if (typeof options.onDecision === 'function') await options.onDecision(call, verdict);
        let allowed = decision === 'allow' || decision === 'log';
        let approvalError = null;
        if (decision === 'require_approval') {
          if (typeof options.approve === 'function') {
            try {
              allowed = Boolean(await options.approve(call, verdict));
            } catch (error) {
              approvalError = error;
              allowed = false;
            }
          }
        }
        if (!allowed) {
          context = appendHistoryEntry(context, call && call.tool);
          if (approvalError) throw approvalError;
          throw new ShieldGraphBlocked(call, verdict);
        }
        try {
          if (typeof execute !== 'function') throw new TypeError('run() requires an executor function');
          const result = await execute(call.args, call);
          context = learnFromResult(call, result, context, SHIELDGRAPH_POLICY);
          return result;
        } catch (error) {
          context = appendHistoryEntry(context, call && call.tool);
          throw error;
        }
      } finally {
        commitQuota();
        if (release) release();
      }
    },
    get context() {
      return context;
    },
    get quotaCounts() {
      return new Map(quotaCounts);
    },
    get log() {
      return log.slice();
    }
  };
  return guard;
}

export default createGuard;
`;

/**
 * @param {Record<string,string>} sources  module file name to source text
 * @param {object} policy  a policy that already passed validatePolicy
 */
export async function compileGuard(sources, policy) {
  for (const name of GUARD_MODULES) {
    if (typeof sources[name] !== 'string') throw new Error(`Missing guard module source ${name}`);
  }
  const policyJson = stableStringify(policy);
  const digest = await sha256Hex(policyJson);
  const body = GUARD_MODULES.map((name) => `// ---- ${name} ----\n${stripRelativeImports(sources[name]).trim()}\n`).join('\n');
  const header = [
    '// shieldgraph-guard.mjs',
    `// Generated by ShieldGraph (policy sha256 ${digest}).`,
    '// Zero dependencies. Runs in Node 22+ and modern browsers.',
    '//',
    "// import { createGuard } from './shieldgraph-guard.mjs';",
    '// const guard = createGuard({ approve: async (call, verdict) => askHuman(call, verdict) });',
    '// guard.addTrusted(userPrompt);',
    "// guard.addUntrusted(fetchedPage, 'web page');",
    '// await guard.run({ tool: "shell_exec", args: { cmd } }, (args, frozenCall) => exec(args.cmd));',
    ''
  ].join('\n');
  const policyBlock = `\nexport const SHIELDGRAPH_POLICY = Object.freeze(${policyJson});\nexport const SHIELDGRAPH_POLICY_SHA256 = '${digest}';\n`;
  return { code: `${header}\n${body}${policyBlock}${RUNTIME}`, digest, policyJson };
}

export async function loadGuardSources(readText) {
  const out = {};
  for (const name of GUARD_MODULES) out[name] = await readText(name);
  return out;
}
