// De-obfuscation pipeline: every layer an attacker uses to hide text from a
// naive filter is peeled off in a fixed, inspectable order.
import { looksLikeProse, truncate } from './util.mjs';

const cp = (...codes) => String.fromCodePoint(...codes);

// Invisible format characters (zero width, soft hyphen, bidi controls).
const INVISIBLE_CODES = [
  0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180e,
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
  0x2066, 0x2067, 0x2068, 0x2069, 0xfeff
];
export const INVISIBLE_SET = new Set(INVISIBLE_CODES);

// Latin lookalikes from Cyrillic and Greek, built from code points so no
// invisible or confusable literal ever sits in this source file.
const CONFUSABLE_PAIRS = [
  [0x0430, 'a'], [0x0435, 'e'], [0x043e, 'o'], [0x0440, 'p'], [0x0441, 'c'],
  [0x0443, 'y'], [0x0445, 'x'], [0x0456, 'i'], [0x0458, 'j'], [0x0455, 's'],
  [0x0501, 'd'], [0x04bb, 'h'], [0x04cf, 'l'], [0x0261, 'g'], [0x051b, 'q'],
  [0x051d, 'w'], [0x0432, 'b'], [0x043a, 'k'], [0x043c, 'm'], [0x043d, 'h'],
  [0x0442, 't'], [0x0410, 'A'], [0x0412, 'B'], [0x0415, 'E'], [0x041a, 'K'],
  [0x041c, 'M'], [0x041d, 'H'], [0x041e, 'O'], [0x0420, 'P'], [0x0421, 'C'],
  [0x0422, 'T'], [0x0425, 'X'], [0x0406, 'I'], [0x0405, 'S'], [0x0408, 'J'],
  [0x03bf, 'o'], [0x03b1, 'a'], [0x03bd, 'v'], [0x03c1, 'p'], [0x03b9, 'i'],
  [0x03ba, 'k'], [0x03c5, 'u'], [0x039f, 'O'], [0x0391, 'A'], [0x0392, 'B'],
  [0x0395, 'E'], [0x0397, 'H'], [0x0399, 'I'], [0x039a, 'K'], [0x039c, 'M'],
  [0x039d, 'N'], [0x03a1, 'P'], [0x03a4, 'T'], [0x03a7, 'X'], [0x0396, 'Z'],
  [0x03a5, 'Y'], [0x0131, 'i'], [0x1e9d, 'f'], [0x0251, 'a'], [0x01c0, 'l']
];
export const CONFUSABLES = new Map(CONFUSABLE_PAIRS.map(([code, latin]) => [cp(code), latin]));

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', sol: '/', colon: ':',
  period: '.', lpar: '(', rpar: ')', comma: ',', excl: '!', num: '#', percnt: '%',
  equals: '=', quest: '?', commat: '@', lsqb: '[', rsqb: ']', lowbar: '_', grave: '`',
  lbrace: '{', rbrace: '}', verbar: '|', vert: '|', Tab: '\t', NewLine: '\n', dollar: '$',
  plus: '+', hyphen: '-', ast: '*', semi: ';', bsol: '\\', Hat: '^', tilde: '~'
};

export function stripInvisible(text) {
  let removed = 0;
  let tagged = '';
  let out = '';
  for (const ch of String(text)) {
    const code = ch.codePointAt(0);
    if (INVISIBLE_SET.has(code)) {
      removed += 1;
      continue;
    }
    // Unicode tag characters (U+E0000 block) mirror ASCII and render as nothing.
    if (code >= 0xe0000 && code <= 0xe007f) {
      removed += 1;
      if (code >= 0xe0020 && code <= 0xe007e) tagged += String.fromCharCode(code - 0xe0000);
      continue;
    }
    // Variation selectors are invisible too.
    if ((code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xe0100 && code <= 0xe01ef)) {
      removed += 1;
      continue;
    }
    out += ch;
  }
  return { text: out, removed, tagged };
}

export function decodeHtmlEntities(text) {
  let count = 0;
  const out = String(text).replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[A-Za-z]{2,10});?/g, (match, body) => {
    let value = null;
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      if (Number.isFinite(code) && code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff)) {
        value = String.fromCodePoint(code);
      }
    } else if (Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, body) && (match.endsWith(';') || body.length <= 4)) {
      value = NAMED_ENTITIES[body];
    }
    if (value === null) return match;
    count += 1;
    return value;
  });
  return { text: out, count };
}

function decodePercentOnce(text) {
  let count = 0;
  const out = String(text).replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    const pieces = run.match(/%[0-9a-fA-F]{2}/g);
    count += pieces.length;
    try {
      return decodeURIComponent(run);
    } catch {
      return pieces.map((p) => String.fromCharCode(parseInt(p.slice(1), 16))).join('');
    }
  });
  return { text: out, count };
}

export function decodePercent(text, maxDepth = 4) {
  let current = String(text);
  let total = 0;
  let rounds = 0;
  for (; rounds < maxDepth; rounds += 1) {
    const step = decodePercentOnce(current);
    if (!step.count || step.text === current) break;
    total += step.count;
    current = step.text;
  }
  return { text: current, count: total, rounds };
}

export function foldConfusables(text) {
  let count = 0;
  let out = '';
  for (const ch of String(text)) {
    const latin = CONFUSABLES.get(ch);
    if (latin) {
      count += 1;
      out += latin;
    } else out += ch;
  }
  return { text: out, count };
}

export function hasMixedScript(word) {
  let latin = false;
  let other = false;
  for (const ch of String(word)) {
    if (/[A-Za-z]/.test(ch)) latin = true;
    else if (CONFUSABLES.has(ch)) other = true;
  }
  return latin && other;
}

function bytesToText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

export function decodeBase64(token) {
  let clean = String(token).replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (clean.length % 4 === 1) return null;
  while (clean.length % 4) clean += '=';
  try {
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytesToText(bytes);
  } catch {
    return null;
  }
}

export function decodeHex(token) {
  const clean = String(token).replace(/\\x/g, '');
  if (clean.length % 2) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytesToText(bytes);
}

// Finds encoded blobs that decode to readable text. Binary results (hashes,
// git SHAs, lockfile integrity values) are rejected by the prose test.
export function extractPayloads(text) {
  const found = [];
  const seen = new Set();
  const source = String(text);
  const push = (kind, encoded, decoded, index) => {
    const key = `${kind}:${encoded}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ kind, encoded, decoded, index });
  };
  for (const match of source.matchAll(/(?:\\x[0-9a-fA-F]{2}){4,}/g)) {
    const decoded = decodeHex(match[0]);
    if (decoded && looksLikeProse(decoded)) push('hex', match[0], decoded, match.index);
  }
  for (const match of source.matchAll(/(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])/g)) {
    const decoded = decodeHex(match[0]);
    if (decoded && looksLikeProse(decoded)) push('hex', match[0], decoded, match.index);
  }
  for (const match of source.matchAll(/(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])/g)) {
    const token = match[0];
    if (/^[0-9A-Fa-f]+$/.test(token) && seen.has(`hex:${token}`)) continue;
    const decoded = decodeBase64(token);
    if (decoded && looksLikeProse(decoded)) push('base64', token, decoded, match.index);
  }
  return found.sort((a, b) => a.index - b.index);
}

export function deobfuscate(input, options = {}) {
  const maxDepth = Number.isInteger(options.maxDepth) ? options.maxDepth : 3;
  const depth = options.depth || 0;
  const original = String(input ?? '');
  const layers = [];
  let text = original;

  const invisible = stripInvisible(text);
  layers.push({ id: 'invisible', label: 'Invisible characters stripped', count: invisible.removed, before: text, after: invisible.text });
  text = invisible.text;

  const entities = decodeHtmlEntities(text);
  layers.push({ id: 'entities', label: 'HTML entities decoded', count: entities.count, before: text, after: entities.text });
  text = entities.text;

  const percent = decodePercent(text);
  layers.push({ id: 'percent', label: 'URL percent-encoding decoded', count: percent.count, rounds: percent.rounds, before: text, after: percent.text });
  text = percent.text;

  // Entities can hide behind percent-encoding and the reverse; one more pass.
  const entities2 = decodeHtmlEntities(text);
  if (entities2.count) {
    layers[1].count += entities2.count;
    text = entities2.text;
  }

  const nfkc = text.normalize('NFKC');
  let nfkcCount = 0;
  if (nfkc !== text) {
    const a = [...text];
    const b = [...nfkc];
    nfkcCount = Math.max(1, a.filter((ch, i) => ch !== b[i]).length);
  }
  layers.push({ id: 'nfkc', label: 'Unicode NFKC compatibility folding', count: nfkcCount, before: text, after: nfkc });
  text = nfkc;

  const folded = foldConfusables(text);
  layers.push({ id: 'confusables', label: 'Homoglyphs folded to Latin', count: folded.count, before: text, after: folded.text });
  text = folded.text;

  const payloads = [];
  if (invisible.tagged) payloads.push({ kind: 'unicode-tags', encoded: '(invisible tag characters)', decoded: invisible.tagged, index: 0, depth });
  if (depth < maxDepth) {
    for (const payload of extractPayloads(text)) {
      const inner = deobfuscate(payload.decoded, { maxDepth, depth: depth + 1 });
      payloads.push({ ...payload, decoded: inner.text, depth });
      for (const nested of inner.payloads) payloads.push(nested);
    }
  }
  layers.push({ id: 'payloads', label: 'Base64, hex and tag payloads extracted', count: payloads.length, before: '', after: payloads.map((p) => truncate(p.decoded, 160)).join('\n') });

  const analysisText = [text, ...payloads.map((p) => p.decoded)].join('\n');
  const changed = layers.filter((layer) => layer.count > 0).map((layer) => layer.id);
  return { original, text, payloads, layers, analysisText, changed };
}
