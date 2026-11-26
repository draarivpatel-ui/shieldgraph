// Shared helpers for every ShieldGraph detector.
// This file is concatenated into the exported guard, so it must import nothing
// and every top-level name must be unique across the guard modules.

export const ACTIONS = ['allow', 'log', 'require_approval', 'deny'];

export function actionRank(action) {
  const index = ACTIONS.indexOf(action);
  return index === -1 ? ACTIONS.length - 1 : index;
}

export function strictestAction(list) {
  let best = 'allow';
  for (const action of list) {
    if (actionRank(action) > actionRank(best)) best = ACTIONS[actionRank(action)];
  }
  return best;
}

export function shannonEntropy(text) {
  if (!text) return 0;
  const counts = new Map();
  for (const ch of text) counts.set(ch, (counts.get(ch) || 0) + 1);
  let bits = 0;
  const total = [...text].length;
  for (const count of counts.values()) {
    const p = count / total;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export function printableRatio(text) {
  if (!text) return 0;
  let good = 0;
  let total = 0;
  for (const ch of text) {
    total += 1;
    const code = ch.codePointAt(0);
    if ((code >= 32 && code < 127) || code === 9 || code === 10 || code === 13) good += 1;
  }
  return total ? good / total : 0;
}

// Reads like language: printable, has spaces between words, and enough letters.
export function looksLikeProse(text) {
  if (!text || text.length < 6) return false;
  if (printableRatio(text) < 0.92) return false;
  const letters = (text.match(/[A-Za-z]/g) || []).length;
  const spaces = (text.match(/[ \t]/g) || []).length;
  const symbols = (text.match(/[^A-Za-z0-9\s]/g) || []).length;
  if (letters / text.length < 0.55) return false;
  if (symbols / text.length > 0.2) return false;
  return spaces >= 1 || /[/.:=]/.test(text);
}

export function collectStrings(value, out = [], path = '') {
  if (typeof value === 'string') out.push({ path, value });
  else if (typeof value === 'number' || typeof value === 'boolean') out.push({ path, value: String(value) });
  else if (Array.isArray(value)) value.forEach((item, i) => collectStrings(item, out, `${path}[${i}]`));
  else if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) collectStrings(value[key], out, path ? `${path}.${key}` : key);
  }
  return out;
}

export function clampScore(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

// Combines independent risk weights the way probabilities of independent events combine.
export function combineWeights(weights) {
  let keep = 1;
  for (const w of weights) keep *= 1 - clampScore(w);
  return clampScore(1 - keep);
}

export function truncate(text, max = 120) {
  const s = String(text ?? '');
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

// Longest common substring, capped so huge pages stay fast.
export function longestCommonRun(a, b, cap = 4000) {
  return longestCommonString(a, b, cap).length;
}

export function longestCommonString(a, b, cap = 4000) {
  const x = String(a).slice(0, cap);
  const y = String(b).slice(0, cap);
  if (!x || !y) return '';
  let prev = new Uint16Array(y.length + 1);
  let cur = new Uint16Array(y.length + 1);
  let best = 0;
  let end = 0;
  for (let i = 1; i <= x.length; i += 1) {
    for (let j = 1; j <= y.length; j += 1) {
      if (x.charCodeAt(i - 1) === y.charCodeAt(j - 1)) {
        cur[j] = prev[j - 1] + 1;
        if (cur[j] > best) {
          best = cur[j];
          end = i;
        }
      } else {
        cur[j] = 0;
      }
    }
    const swap = prev;
    prev = cur;
    cur = swap;
    cur.fill(0);
  }
  return x.slice(end - best, end);
}
