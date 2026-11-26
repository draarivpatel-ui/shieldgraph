// Shared helpers for every ShieldGraph detector.
// This file is concatenated into the exported guard, so it must import nothing
// and every top-level name must be unique across the guard modules.

export const ACTIONS = ['allow', 'log', 'require_approval', 'deny'];

// Hard work limits are independent of policy. A user can lower the per-tool
// argument cap, but cannot raise the guard's ceiling enough to stall evaluation.
export const WORK_LIMITS = Object.freeze({
  maxArgumentChars: 16000,
  maxCollectedStrings: 256,
  maxCollectDepth: 10,
  maxContextItems: 48,
  maxContextChars: 131072,
  maxSourceChars: 32768,
  maxPairwiseComparisons: 24,
  maxPairwiseCharWork: 98304
});

export function hasOwn(object, key) {
  return Object.hasOwn(object, key);
}

export function createWorkBudget() {
  return { pairwiseComparisons: 0, pairwiseCharWork: 0, exceeded: [] };
}

export function exceedBudget(work, reason) {
  if (!work) return;
  if (!work.exceeded.includes(reason)) work.exceeded.push(reason);
}

// Reserves one pairwise provenance comparison before doing it. The character
// work charged here tracks the linear-time matcher below, not the old quadratic
// dynamic program, so the limits reflect real work while still bounding N x M.
export function reservePairwiseComparison(work, a, b, cap = 4000) {
  if (!work) return true;
  if (work.pairwiseComparisons + 1 > WORK_LIMITS.maxPairwiseComparisons) {
    exceedBudget(work, `Too many pairwise provenance comparisons (cap ${WORK_LIMITS.maxPairwiseComparisons}).`);
    return false;
  }
  const chars = Math.min(String(a).length, cap) + Math.min(String(b).length, cap);
  if (work.pairwiseCharWork + chars > WORK_LIMITS.maxPairwiseCharWork) {
    exceedBudget(work, `Pairwise provenance scan work exceeds the cap (${WORK_LIMITS.maxPairwiseCharWork} chars).`);
    return false;
  }
  work.pairwiseComparisons += 1;
  work.pairwiseCharWork += chars;
  return true;
}

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

export function collectStrings(value, out = [], path = '', work = null, active = new Set(), depth = 0) {
  if (work && out.length >= WORK_LIMITS.maxCollectedStrings) {
    exceedBudget(work, `Argument structure has more than ${WORK_LIMITS.maxCollectedStrings} scalar values.`);
    return out;
  }
  if (work && depth > WORK_LIMITS.maxCollectDepth) {
    exceedBudget(work, `Argument structure is nested deeper than ${WORK_LIMITS.maxCollectDepth} levels.`);
    return out;
  }
  if (typeof value === 'string') out.push({ path, value });
  else if (typeof value === 'number' || typeof value === 'boolean') out.push({ path, value: String(value) });
  else if (Array.isArray(value)) {
    if (active.has(value)) {
      if (work) exceedBudget(work, 'Argument structure contains a cycle.');
      return out;
    }
    active.add(value);
    value.forEach((item, i) => collectStrings(item, out, `${path}[${i}]`, work, active, depth + 1));
    active.delete(value);
  } else if (value && typeof value === 'object') {
    if (active.has(value)) {
      if (work) exceedBudget(work, 'Argument structure contains a cycle.');
      return out;
    }
    active.add(value);
    for (const key of Object.keys(value)) collectStrings(value[key], out, path ? `${path}.${key}` : key, work, active, depth + 1);
    active.delete(value);
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

// Longest common substring, capped so huge pages stay fast. The suffix
// automaton makes each comparison linear in the two capped inputs instead of
// quadratic, so provenance stays usable on long pages and commands.
export function longestCommonRun(a, b, cap = 4000) {
  return longestCommonString(a, b, cap).length;
}

export function longestCommonString(a, b, cap = 4000) {
  const x = String(a).slice(0, cap);
  const y = String(b).slice(0, cap);
  if (!x || !y) return '';

  const states = [{ len: 0, link: -1, next: new Map() }];
  let last = 0;
  const extend = (ch) => {
    const curIndex = states.length;
    states.push({ len: states[last].len + 1, link: 0, next: new Map() });
    let p = last;
    while (p !== -1 && !states[p].next.has(ch)) {
      states[p].next.set(ch, curIndex);
      p = states[p].link;
    }
    if (p === -1) {
      states[curIndex].link = 0;
    } else {
      const q = states[p].next.get(ch);
      if (states[p].len + 1 === states[q].len) {
        states[curIndex].link = q;
      } else {
        const clone = states.length;
        states.push({ len: states[p].len + 1, link: states[q].link, next: new Map(states[q].next) });
        while (p !== -1 && states[p].next.get(ch) === q) {
          states[p].next.set(ch, clone);
          p = states[p].link;
        }
        states[q].link = clone;
        states[curIndex].link = clone;
      }
    }
    last = curIndex;
  };
  for (let i = 0; i < x.length; i += 1) extend(x[i]);

  let state = 0;
  let length = 0;
  let best = 0;
  let bestEnd = 0;
  for (let i = 0; i < y.length; i += 1) {
    const ch = y[i];
    while (state !== 0 && !states[state].next.has(ch)) {
      state = states[state].link;
      length = states[state].len;
    }
    if (states[state].next.has(ch)) {
      state = states[state].next.get(ch);
      length += 1;
    } else {
      state = 0;
      length = 0;
    }
    if (length > best) {
      best = length;
      bestEnd = i + 1;
    }
  }
  return y.slice(bestEnd - best, bestEnd);
}
