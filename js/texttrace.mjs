const MAX_SERIALIZE_DEPTH = 4;
const MAX_SERIALIZE_NODES = 80;
const MAX_SERIALIZE_KEYS = 8;
const MAX_SERIALIZE_ITEMS = 8;
const MAX_SERIALIZE_STRING = 120;
const MAX_SERIALIZE_KEY = 48;

function capLength(text, maxChars) {
  const value = String(text);
  const cap = Math.max(4, Number.isFinite(maxChars) ? Math.floor(maxChars) : 120);
  return value.length > cap ? `${value.slice(0, cap - 3)}...` : value;
}

function snapshotValue(value, state, depth) {
  if (value === null) return null;
  const type = typeof value;
  if (type === 'string') return capLength(value, MAX_SERIALIZE_STRING);
  if (type === 'number') return Number.isFinite(value) ? value : String(value);
  if (type === 'boolean') return value;
  if (type === 'bigint') return `bigint ${String(value)}`;
  if (type === 'undefined') return '[undefined]';
  if (type === 'symbol') return String(value);
  if (type === 'function') return '[function]';
  if (depth >= MAX_SERIALIZE_DEPTH || state.nodes >= MAX_SERIALIZE_NODES) return '[truncated]';
  if (state.active.has(value)) return '[circular]';
  state.nodes += 1;
  state.active.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      const count = Math.min(value.length, MAX_SERIALIZE_ITEMS);
      for (let i = 0; i < count; i += 1) {
        let child = '[throwing getter]';
        try {
          child = value[i];
        } catch { /* keep the unreadable slot marker */ }
        out.push(snapshotValue(child, state, depth + 1));
      }
      if (value.length > count) out.push(`[${value.length - count} more items]`);
      return out;
    }
    const out = Object.create(null);
    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      return '[unreadable object]';
    }
    for (const key of keys.slice(0, MAX_SERIALIZE_KEYS)) {
      let child = '[throwing getter]';
      try {
        child = value[key];
      } catch { /* keep the unreadable property marker */ }
      out[capLength(key, MAX_SERIALIZE_KEY)] = snapshotValue(child, state, depth + 1);
    }
    if (keys.length > MAX_SERIALIZE_KEYS) out[`${keys.length - MAX_SERIALIZE_KEYS} more keys`] = '[truncated]';
    return out;
  } finally {
    state.active.delete(value);
  }
}

function objectTypeFallback(value) {
  try {
    return Object.prototype.toString.call(value);
  } catch {
    return '[unprintable object]';
  }
}

export function safeValueString(value, maxChars = 120) {
  let text;
  if (typeof value === 'string') text = value;
  else if (value === null) text = 'null';
  else if (typeof value !== 'object' && typeof value !== 'function') text = String(value);
  else {
    let serialized;
    try {
      serialized = JSON.stringify(snapshotValue(value, { active: new Set(), nodes: 0 }, 0));
    } catch {
      serialized = undefined;
    }
    text = typeof serialized === 'string' ? serialized : objectTypeFallback(value);
  }
  return capLength(text, maxChars);
}

export function traceArgumentText(node, arg, value, outcome, formatValue = safeValueString) {
  const provenance = node && node.provenance && typeof node.provenance === 'object' ? node.provenance : null;
  const trace = provenance && Object.prototype.hasOwnProperty.call(provenance, arg) ? provenance[arg] : null;
  const sources = trace && Array.isArray(trace.sources) ? trace.sources : [];
  let source = 'no untrusted source match (origin not established)';
  if (sources.length) {
    const seen = sources.map((s) => `${s && s.origin !== undefined && s.origin !== null ? safeValueString(s.origin, 80) : 'unknown source'} (${s && s.how !== undefined && s.how !== null ? safeValueString(s.how, 40) : 'match'})`).join(' or ');
    source = trace.endorsed ? `user-endorsed value also seen in ${seen}` : seen;
  }
  const findings = node && Array.isArray(node.findings) ? node.findings : [];
  const matched = findings.filter((f) => !f.arg || f.arg === arg).map((f) => f.rule);
  const rulesText = matched.length ? matched.join(', ') : 'no rule matched';
  const shown = formatValue(value);
  return `${source} -> ${arg}${shown ? ` "${shown}"` : ''} -> ${rulesText} -> ${outcome}`;
}
