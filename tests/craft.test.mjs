import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { SCENARIOS } from '../js/scenarios.mjs';
import { traceArgumentText } from '../js/texttrace.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const cp = (...c) => String.fromCodePoint(...c);

function listFiles(dir, out = []) {
  for (const name of fs.readdirSync(path.join(root, dir))) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const rel = path.join(dir, name);
    const st = fs.statSync(path.join(root, rel));
    if (st.isDirectory()) listFiles(rel, out);
    else if (/\.(html|css|mjs|js|md|json|py|svg|txt)$/.test(name)) out.push(rel);
  }
  return out;
}
const TEXT_FILES = listFiles('.');
const css = read('styles.css');
const html = read('index.html');

// ---------- writing rules ----------

// Built from code points so this file never holds the characters it hunts.
const BANNED_CHARS = [[cp(0x2014), 'em dash'], [cp(0x2013), 'en dash'], [cp(0x00b7), 'middle dot'], [cp(0x2022), 'bullet']];
const BANNED_ENTITIES = /&(mdash|ndash|middot|bull);|&#(8212|8211|183|8226);|&#x(2014|2013|b7|2022);/i;

function dashScan(text) {
  const hits = [];
  for (const [ch, name] of BANNED_CHARS) if (text.includes(ch)) hits.push(name);
  if (BANNED_ENTITIES.test(text)) hits.push('dash or dot entity');
  if (/\\u(2014|2013|00b7|2022)/i.test(text)) hits.push('escaped dash or dot');
  return hits;
}

test('dash scanner catches a planted probe of every banned form', () => {
  assert.deepEqual(dashScan(`a${cp(0x2014)}b`), ['em dash']);
  assert.deepEqual(dashScan(`a${cp(0x2013)}b`), ['en dash']);
  assert.deepEqual(dashScan('a&mdash;b'), ['dash or dot entity']);
  assert.deepEqual(dashScan('a&#8211;b'), ['dash or dot entity']);
  assert.deepEqual(dashScan(`x ${cp(0x00b7)} y`), ['middle dot']);
  assert.deepEqual(dashScan('plain - hyphen'), []);
});
test('no em dashes, en dashes or dot separators in any shipped text file', () => {
  assert.ok(TEXT_FILES.length >= 20, `only ${TEXT_FILES.length} files scanned`);
  for (const file of TEXT_FILES) {
    if (file === path.join('tests', 'craft.test.mjs')) continue;
    assert.deepEqual(dashScan(read(file)), [], file);
  }
});
test('no eyebrow, kicker or tagline elements anywhere in the UI', () => {
  for (const file of ['index.html', 'styles.css', 'js/app.mjs', 'js/graph.mjs', 'js/report.mjs']) {
    assert.doesNotMatch(read(file), /eyebrow|kicker|overline|tagline|subtitle|subhead/i, file);
  }
});
test('no all-caps letter-spaced labels in the stylesheet', () => {
  assert.doesNotMatch(css, /text-transform:\s*uppercase/);
});

// ---------- page contract ----------

test('index.html declares language, viewport, title and description', () => {
  assert.match(html, /<html lang="en"/);
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1">/);
  assert.match(html, /<title>ShieldGraph<\/title>/);
  assert.match(html, /<meta name="description" content="[^"]{60,}">/);
});
test('a strict Content Security Policy forbids every outside origin', () => {
  const m = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(m);
  for (const part of ["default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'"]) assert.ok(m[1].includes(part), part);
  assert.doesNotMatch(m[1], /unsafe-inline|unsafe-eval|https?:/);
});
test('UI code and styles reference no outside URL', () => {
  for (const file of ['index.html', 'styles.css', 'js/app.mjs', 'js/graph.mjs', 'js/report.mjs', 'js/compiler.mjs']) {
    const urls = (read(file).match(/https?:\/\/[^\s"'`)]+/g) || []).filter((u) => !u.startsWith('http://www.w3.org/2000/svg'));
    assert.deepEqual(urls, [], file);
  }
});
test('no inline script or inline event handler in index.html', () => {
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /\son[a-z]+="/);
});
test('UI code never writes markup from strings', () => {
  for (const file of ['js/app.mjs', 'js/graph.mjs', 'js/report.mjs']) {
    assert.doesNotMatch(read(file), /\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write/, file);
  }
});
test('text trace never calls an unmatched argument trusted', () => {
  const app = read('js/app.mjs');
  const trace = read('js/texttrace.mjs');
  assert.ok(trace.includes('no untrusted source match (origin not established)'));
  assert.ok(!app.includes('trusted user or planner input'));
  assert.ok(!trace.includes('trusted user or planner input'));
});

test('text trace renders prototype-named arguments without inherited lookups or missing-source throws', () => {
  const node = {
    args: { toString: 'copied', constructor: 'built' },
    provenance: {},
    findings: [{ rule: 'badArgs', arg: 'toString' }]
  };
  for (const arg of ['toString', 'constructor', '__proto__', 'valueOf']) {
    const line = traceArgumentText(node, arg, 'copied', 'Filesystem read not reached (Blocked)', (v) => String(v));
    assert.ok(line.includes('origin not established'), arg);
    assert.ok(line.includes(`-> ${arg}`), arg);
  }
  const broken = { ...node, provenance: { toString: { endorsed: false } } };
  assert.ok(traceArgumentText(broken, 'toString', 'copied', 'Filesystem read not reached (Blocked)', (v) => String(v)).includes('origin not established'));
});
test('UI code never sets a style attribute (blocked by the CSP)', () => {
  for (const file of ['js/app.mjs', 'js/graph.mjs', 'js/report.mjs']) {
    assert.doesNotMatch(read(file), /setAttribute\(\s*'style'|\bstyle:\s*`/, file);
  }
});
test('every view is a labelled tabpanel with a matching tab', () => {
  for (const v of ['workbench', 'playground', 'benchmark', 'policy']) {
    assert.match(html, new RegExp(`role="tab" id="tab-${v}" aria-controls="view-${v}"`));
    assert.match(html, new RegExp(`id="view-${v}" role="tabpanel" aria-labelledby="tab-${v}"`));
  }
});
test('every icon-only button has an accessible name', () => {
  for (const m of html.matchAll(/<button[^>]*class="icon-btn[^"]*"[^>]*>/g)) assert.match(m[0], /aria-label="[^"]{4,}"/, m[0]);
});
test('every form control has a label', () => {
  for (const m of html.matchAll(/<(textarea|select) id="([^"]+)"/g)) {
    assert.match(html, new RegExp(`<label for="${m[2]}">`), m[2]);
  }
});
test('skip link targets the main region', () => {
  assert.match(html, /<a class="skip" href="#main">/);
  assert.match(html, /<main id="main"/);
});

// ---------- stylesheet contract ----------

test('focus rings are visible and themed', () => {
  assert.match(css, /:focus-visible\s*\{[^}]*outline:\s*2\.5px solid var\(--focus\)/);
});
test('motion respects prefers-reduced-motion', () => {
  const anims = [...css.matchAll(/animation:\s*[a-z]/g)].length;
  assert.ok(anims > 0);
  const block = css.slice(css.indexOf('@media (prefers-reduced-motion: no-preference)'));
  assert.ok(block.length > 0);
  const before = css.slice(0, css.indexOf('@media (prefers-reduced-motion: no-preference)'));
  assert.doesNotMatch(before, /animation:\s*[a-z]/, 'animations must live inside the no-preference block');
});
test('no smooth scrolling and no colour transitions on stateful controls', () => {
  assert.doesNotMatch(css, /scroll-behavior:\s*smooth/);
  assert.doesNotMatch(css, /transition/);
});
test('dark theme exists for system preference and for the manual toggle', () => {
  assert.match(css, /@media \(prefers-color-scheme: dark\)\s*\{\s*:root:not\(\[data-theme="light"\]\)/);
  assert.match(css, /:root\[data-theme="dark"\]\s*\{/);
  assert.match(css, /body\s*\{[^}]*background:\s*var\(--paper\)/);
});
test('print styles target one US Letter page and override both themes', () => {
  assert.match(css, /@page\s*\{\s*size:\s*letter/);
  assert.match(css, /@media print\s*\{[\s\S]*:root, :root\[data-theme="dark"\]/);
});
test('the display font is self-hosted with swap and a system fallback', () => {
  assert.match(css, /@font-face\s*\{[^}]*src:\s*url\("fonts\/shieldgraph-plot\.woff2"\)[^}]*font-display:\s*swap/);
  assert.match(css, /--font-display:\s*"ShieldGraph Plot", ui-sans-serif/);
});

// ---------- WCAG AA contrast, computed from the real tokens ----------

function tokens(block) {
  const out = {};
  for (const m of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)) out[m[1]] = m[2];
  return out;
}
function lum(hex) {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
function ratio(a, b) {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
const light = tokens(css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {'))));
const darkStart = css.indexOf(':root[data-theme="dark"] {');
const dark = tokens(css.slice(darkStart, css.indexOf('}', darkStart)));

test('contrast helper matches known WCAG values', () => {
  assert.ok(Math.abs(ratio('#000000', '#ffffff') - 21) < 1e-9);
  assert.ok(Math.abs(ratio('#777777', '#ffffff') - 4.48) < 0.01);
});
for (const [name, t] of [['light', light], ['dark', dark]]) {
  test(`${name} theme: text tokens reach 4.5:1 on every surface`, () => {
    for (const fg of ['ink', 'ink-2', 'ink-3']) {
      for (const bg of ['paper', 'panel', 'panel-2', 'code-bg']) {
        const r = ratio(t[fg], t[bg]);
        assert.ok(r >= 4.5, `${fg} on ${bg} is ${r.toFixed(2)}`);
      }
    }
  });
  test(`${name} theme: every status colour reaches 4.5:1 on its tint and on panels`, () => {
    for (const st of ['allow', 'log', 'approval', 'deny', 'taint']) {
      for (const bg of [`${st}-bg`, 'panel', 'paper']) {
        const r = ratio(t[st], t[bg]);
        assert.ok(r >= 4.5, `${st} on ${bg} is ${r.toFixed(2)}`);
      }
    }
  });
  test(`${name} theme: accent and inverted buttons reach 4.5:1`, () => {
    assert.ok(ratio(t.accent, t.panel) >= 4.5, 'accent on panel');
    assert.ok(ratio(t.paper, t.ink) >= 4.5, 'paper on ink (primary buttons)');
    assert.ok(ratio(t.focus, t.paper) >= 3, 'focus ring against the page');
  });
}

// ---------- custom display font ----------

const UIBASE = ['cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post', 'cvt ', 'fpgm', 'glyf', 'loca', 'prep'];
function woff2Cmap(file) {
  const b = fs.readFileSync(file);
  assert.equal(b.toString('latin1', 0, 4), 'wOF2');
  const numTables = b.readUInt16BE(12);
  const compressed = b.readUInt32BE(20);
  let o = 48;
  const u128 = () => {
    let v = 0;
    for (let i = 0; i < 5; i += 1) {
      const x = b[o++];
      v = v * 128 + (x & 127);
      if (!(x & 128)) return v;
    }
    throw new Error('bad UIntBase128');
  };
  const dir = [];
  for (let i = 0; i < numTables; i += 1) {
    const flags = b[o++];
    let tag;
    if ((flags & 63) === 63) {
      tag = b.toString('latin1', o, o + 4);
      o += 4;
    } else tag = UIBASE[flags & 63] || `#${flags & 63}`;
    const version = (flags >> 6) & 3;
    let len = u128();
    const transformed = tag === 'glyf' || tag === 'loca' ? version === 0 : version !== 0;
    if (transformed) len = u128();
    dir.push({ tag, len });
  }
  const data = zlib.brotliDecompressSync(b.subarray(o, o + compressed));
  let off = 0;
  for (const t of dir) {
    t.off = off;
    off += t.len;
  }
  const cmap = dir.find((t) => t.tag === 'cmap');
  const base = cmap.off;
  const count = data.readUInt16BE(base + 2);
  const codes = new Set();
  for (let i = 0; i < count; i += 1) {
    const sub = base + data.readUInt32BE(base + 4 + i * 8 + 4);
    if (data.readUInt16BE(sub) !== 4) continue;
    const segX2 = data.readUInt16BE(sub + 6);
    const ends = sub + 14;
    const starts = ends + segX2 + 2;
    for (let s = 0; s < segX2 / 2; s += 1) {
      const end = data.readUInt16BE(ends + s * 2);
      const start = data.readUInt16BE(starts + s * 2);
      if (start === 0xffff) continue;
      for (let c = start; c <= end; c += 1) codes.add(c);
    }
  }
  return codes;
}
const glyphs = woff2Cmap(path.join(root, 'fonts', 'shieldgraph-plot.woff2'));

test('the display font is a real WOFF2 with a Unicode cmap', () => {
  assert.ok(glyphs.size >= 75, `${glyphs.size} code points`);
  assert.ok(fs.statSync(path.join(root, 'fonts', 'shieldgraph-plot.woff2')).size < 24 * 1024);
});
test('the font covers A-Z, a-z, 0-9 and heading punctuation', () => {
  const need = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;-()/?!\'"';
  for (const ch of need) assert.ok(glyphs.has(ch.codePointAt(0)), `missing ${JSON.stringify(ch)}`);
});
test('every character of every heading the UI renders has a glyph', () => {
  const headings = [
    'ShieldGraph', 'Attacks', 'Benign workflows', 'What happens', 'Inspector', 'Red-team playground', 'Benchmark',
    'Decision matrix', 'Policy compiler', 'Export', 'Rules', 'Firewall verdict', 'Matched rules', 'Taint lineage',
    'Payload analysis', 'Arguments', 'Instruction', 'Injection signals', 'De-obfuscation', 'Raw content', 'Plan',
    'Context taint', 'Decoded path', 'Decoded cmd', 'Decoded url', 'Decoded markdown', 'Decoded body', 'Decoded to_account',
    'ShieldGraph Security Audit', 'Detection by policy', 'Scenario results under Custom from Zero-Trust', 'Rule set', 'Egress allowlist',
    ...SCENARIOS.map((s) => s.title)
  ];
  for (const text of headings) for (const ch of text) assert.ok(glyphs.has(ch.codePointAt(0)), `${JSON.stringify(ch)} in "${text}"`);
});
test('the font build script is committed next to the font', () => {
  assert.ok(fs.existsSync(path.join(root, 'tools', 'build-font.py')));
});

// ---------- docs ----------

test('DEVPOST_SUBMISSION.md prose has no colons and backticked dollar amounts', () => {
  const p = path.join(root, 'DEVPOST_SUBMISSION.md');
  if (!fs.existsSync(p)) return;
  let inCode = false;
  for (const [i, line] of read('DEVPOST_SUBMISSION.md').split('\n').entries()) {
    if (line.startsWith('```')) inCode = !inCode;
    if (inCode || line.startsWith('|') || /^\s*$/.test(line)) continue;
    const prose = line.replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '').replace(/\]\([^)]*\)/g, ']');
    assert.ok(!prose.includes(':'), `line ${i + 1}: ${line}`);
    assert.ok(!/(^|[^`])\$\d/.test(line), `unwrapped dollar amount on line ${i + 1}`);
  }
});
