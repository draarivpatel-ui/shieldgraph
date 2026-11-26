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

function frozenVerdict(rawVerdict) {
  try {
    return cloneGeneratedFrozen(rawVerdict);
  } catch {
    return budgetVerdict('Guard verdict exceeds the internal copy budget.');
  }
}

function quotaWithReservations(quotaCounts, reservations, policy) {
  const tools = policy && policy.tools && typeof policy.tools === 'object' ? policy.tools : {};
  const merged = new Map();
  for (const [tool, count] of quotaCounts) if (hasOwn(tools, tool)) merged.set(tool, count);
  for (const [tool, count] of reservations) {
    if (hasOwn(tools, tool)) merged.set(tool, (merged.get(tool) || 0) + count);
  }
  return merged;
}

function copyContextValue(value, state, depth) {
  if (!value || typeof value !== 'object') return value;
  if (depth > 32) throw new Error('Context snapshot is nested too deeply.');
  if (state.active.has(value)) throw new Error('Context snapshot contains a cycle.');
  state.active.add(value);
  const copy = Array.isArray(value) ? [] : Object.create(null);
  try {
    for (const key of Object.keys(value)) {
      state.keys += 1;
      if (state.keys > 131072) throw new Error('Context snapshot has too many keys.');
      Object.defineProperty(copy, key, {
        value: copyContextValue(value[key], state, depth + 1),
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

function snapshotContext(context) {
  return copyContextValue(context, { keys: 0, active: new Set() }, 0);
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
    if (!hasOwn(SHIELDGRAPH_POLICY.tools, tool)) return () => {};
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
  const quotaContext = () => ({ ...context, quotaCounts: quotaWithReservations(quotaCounts, reservations, SHIELDGRAPH_POLICY) });
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
        recordQuotaCall(quotaCounts, tool, SHIELDGRAPH_POLICY);
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
      return snapshotContext(context);
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
