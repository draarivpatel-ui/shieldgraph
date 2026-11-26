// ShieldGraph workbench UI.
import { SCENARIOS, getScenario } from './scenarios.mjs';
import { analyzeScenario, presetPolicy, runBenchmark } from './engine.mjs';
import { PRESET_ORDER, RULES, TOOL_CATALOG, validatePolicy, clonePolicy } from './policy.mjs';
import { compileGuard, loadGuardSources, stableStringify, sha256Hex } from './compiler.mjs';
import { renderGraph, STATUS_TEXT, STATUS_ICON } from './graph.mjs';
import { renderReport } from './report.mjs';
import { scoreInjection } from './injection.mjs';

const $ = (sel) => document.querySelector(sel);
const LABELS = { permissive: 'Permissive', balanced: 'Balanced', zeroTrust: 'Zero-Trust', custom: 'Custom' };
const TABS = ['workbench', 'playground', 'benchmark', 'policy'];
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function icon(id, cls = 'ico') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', cls);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#${id}`);
  svg.append(use);
  return svg;
}

function badge(status, extra = '') {
  return h('span', { class: `badge s-${status} ${extra}`.trim() }, icon(STATUS_ICON[status] || 'i-log'), h('span', {}, STATUS_TEXT[status] || status));
}

function meter(value, label = 'Risk') {
  const v = Math.max(0, Math.min(100, Math.round(value)));
  const band = v >= 80 ? 'high' : v >= 40 ? 'mid' : 'low';
  // CSSOM, not a style attribute, so the strict CSP (style-src 'self') allows it.
  const fill = h('span', { class: 'meter-fill' });
  fill.style.setProperty('--v', String(v));
  return h('div', { class: `meter m-${band}`, role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': v, 'aria-label': `${label} ${v} of 100` },
    h('span', { class: 'meter-l' }, label),
    h('span', { class: 'meter-track' }, fill),
    h('span', { class: 'meter-v' }, String(v)));
}

function pre(text, cls = '') {
  return h('pre', { class: `code ${cls}`.trim() }, h('code', {}, String(text)));
}

// ---------- state ----------

const state = {
  tab: 'workbench',
  scenarioId: SCENARIOS[0].id,
  presetId: 'balanced',
  custom: null,
  step: null,
  selectedId: null,
  playing: null,
  cache: new Map(),
  bench: null,
  digest: ''
};

function policyFor(key) {
  if (key === 'custom') return state.custom;
  if (!state.cache.has(`policy:${key}`)) state.cache.set(`policy:${key}`, presetPolicy(key));
  return state.cache.get(`policy:${key}`);
}

function activePolicy() {
  return policyFor(state.presetId);
}

function analysisFor(scenarioId, key = state.presetId) {
  const cacheKey = `run:${key}:${scenarioId}`;
  if (!state.cache.has(cacheKey)) state.cache.set(cacheKey, analyzeScenario(getScenario(scenarioId), policyFor(key)));
  return state.cache.get(cacheKey);
}

function benchKeys() {
  return state.custom ? [...PRESET_ORDER, 'custom'] : [...PRESET_ORDER];
}

function benchmarks() {
  if (!state.bench) {
    state.bench = {};
    for (const key of benchKeys()) state.bench[key] = runBenchmark(SCENARIOS, policyFor(key));
  }
  return state.bench;
}

function invalidateCustom() {
  for (const k of [...state.cache.keys()]) if (k.startsWith('run:custom:')) state.cache.delete(k);
  state.bench = null;
}

// ---------- persistence ----------

function readHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [tab, query = ''] = raw.split('?');
  const params = new URLSearchParams(query);
  if (TABS.includes(tab)) state.tab = tab;
  const s = params.get('s');
  if (s && getScenario(s)) state.scenarioId = s;
  const p = params.get('p');
  if (p && PRESET_ORDER.includes(p)) state.presetId = p;
  const n = params.get('n');
  if (n) state.selectedId = n;
}

function writeHash() {
  const params = new URLSearchParams({ s: state.scenarioId, p: state.presetId === 'custom' ? 'balanced' : state.presetId });
  if (state.selectedId) params.set('n', state.selectedId);
  history.replaceState(null, '', `#/${state.tab}?${params}`);
}

function storeGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function storeSet(key, value) {
  try { localStorage.setItem(key, value); } catch { /* storage blocked; theme still works for this visit */ }
}

// ---------- theme ----------

function effectiveTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === 'light' || set === 'dark') return set;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function syncThemeButton() {
  const dark = effectiveTheme() === 'dark';
  const btn = $('#theme-toggle');
  btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  btn.replaceChildren(icon(dark ? 'i-sun' : 'i-moon', ''));
}

function initTheme() {
  const saved = storeGet('shieldgraph-theme');
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
  syncThemeButton();
  $('#theme-toggle').addEventListener('click', () => {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    storeSet('shieldgraph-theme', next);
    syncThemeButton();
  });
}

// ---------- tabs ----------

function setTab(tab, focus = false) {
  state.tab = tab;
  for (const t of TABS) {
    const btn = $(`#tab-${t}`);
    const on = t === tab;
    btn.setAttribute('aria-selected', on ? 'true' : 'false');
    btn.tabIndex = on ? 0 : -1;
    $(`#view-${t}`).hidden = !on;
    if (on && focus) btn.focus();
  }
  stopPlay();
  render();
}

function initTabs() {
  const list = $('.tabs');
  list.addEventListener('click', (e) => {
    const btn = e.target.closest('[role="tab"]');
    if (btn) setTab(btn.id.replace('tab-', ''));
  });
  list.addEventListener('keydown', (e) => {
    const i = TABS.indexOf(state.tab);
    let next = null;
    if (e.key === 'ArrowRight') next = TABS[(i + 1) % TABS.length];
    if (e.key === 'ArrowLeft') next = TABS[(i + TABS.length - 1) % TABS.length];
    if (e.key === 'Home') next = TABS[0];
    if (e.key === 'End') next = TABS[TABS.length - 1];
    if (next) {
      e.preventDefault();
      setTab(next, true);
    }
  });
}

// ---------- presets ----------

function syncPresetRadios() {
  for (const input of document.querySelectorAll('input[name="preset"]')) input.checked = input.value === state.presetId;
  $('.seg-custom').hidden = !state.custom;
}

function initPresets() {
  $('#preset-group').addEventListener('change', (e) => {
    if (e.target.name !== 'preset') return;
    state.presetId = e.target.value;
    state.step = null;
    stopPlay();
    loadPolicyEditor();
    render();
  });
}

// ---------- workbench ----------

function defaultSelection(run) {
  const tools = run.nodes.filter((n) => n.kind === 'tool');
  const hit = tools.find((n) => n.decision === 'deny') || tools.find((n) => n.decision === 'require_approval') || tools[0];
  return hit ? hit.id : run.nodes[0].id;
}

function renderList() {
  for (const label of ['attack', 'benign']) {
    const ul = $(`#list-${label}`);
    const items = SCENARIOS.filter((s) => s.label === label).map((s) => {
      const run = analysisFor(s.id);
      const current = s.id === state.scenarioId;
      return h('li', {},
        h('button', {
          type: 'button', class: 'scn', 'data-id': s.id, 'aria-current': current ? 'true' : null,
          onclick: () => selectScenario(s.id)
        },
        icon(STATUS_ICON[run.verdict], `ico s-${run.verdict}`),
        h('span', { class: 'scn-t' }, s.title),
        h('span', { class: `scn-v s-${run.verdict}` }, STATUS_TEXT[run.verdict])));
    });
    ul.replaceChildren(...items);
  }
}

function selectScenario(id, focusList = false) {
  state.scenarioId = id;
  state.selectedId = null;
  state.step = null;
  stopPlay();
  render();
  const btn = document.querySelector(`.scn[data-id="${CSS.escape(id)}"]`);
  const rail = $('.rail');
  if (btn && rail.scrollWidth > rail.clientWidth) {
    // Strip layout: bring the chosen card into view sideways without moving the page.
    const b = btn.getBoundingClientRect();
    const r = rail.getBoundingClientRect();
    if (b.left < r.left || b.right > r.right) rail.scrollLeft += b.left - r.left - 24;
  }
  if (focusList) btn?.focus({ preventScroll: true });
}

function initListKeys() {
  $('.rail').addEventListener('keydown', (e) => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key) || !e.target.classList.contains('scn')) return;
    e.preventDefault();
    const ids = SCENARIOS.map((s) => s.id);
    const i = ids.indexOf(e.target.dataset.id);
    const next = ids[(i + (e.key === 'ArrowDown' ? 1 : ids.length - 1)) % ids.length];
    selectScenario(next, true);
  });
}

function renderStage(run) {
  const s = run.scenario;
  $('#scn-title').textContent = s.title;
  const tools = run.nodes.filter((n) => n.kind === 'tool');
  $('#scn-verdict').replaceChildren(badge(run.verdict, 'badge-lg'), meter(run.risk));
  $('#scn-summary').textContent = s.summary;
  const facts = [
    ['Category', s.category],
    ['Ground truth', s.label === 'attack' ? 'Attack' : 'Benign workflow'],
    ['Tool calls', `${tools.length} (${tools.filter((n) => n.decision === 'deny').length} blocked, ${tools.filter((n) => n.decision === 'require_approval').length} held)`],
    ['Policy', LABELS[state.presetId]]
  ];
  $('#scn-facts').replaceChildren(...facts.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
  renderGraph($('#graph'), run, { step: state.step, selectedId: state.selectedId, onSelect: selectNode });
  const total = run.nodes.length;
  const shown = state.step == null ? total : state.step;
  const at = state.step == null ? null : run.nodes[state.step - 1];
  $('#step-out').textContent = state.step == null ? `Full trace, ${total} steps` : `Step ${shown} of ${total}: ${at.kind === 'tool' ? `${at.tool} ${STATUS_TEXT[at.decision].toLowerCase()}` : at.label}`;
  $('#step-prev').disabled = state.step === null || state.step <= 1;
  $('#step-next').disabled = state.step !== null && state.step >= total;
  $('#step-reset').disabled = state.step === null;
  const playing = Boolean(state.playing);
  const play = $('#step-play');
  play.setAttribute('aria-label', playing ? 'Pause playback' : 'Play the trace step by step');
  play.replaceChildren(icon(playing ? 'i-pause' : 'i-play', ''));
}

function selectNode(id) {
  state.selectedId = id;
  render();
}

function section(title, ...body) {
  return h('section', { class: 'insp-sec' }, h('h3', {}, title), ...body);
}

function findingsTable(findings) {
  if (!findings.length) return h('p', { class: 'muted' }, 'No rule matched. The call passes with the tool\'s base action.');
  return h('ul', { class: 'findings' }, findings.map((f) => h('li', {},
    h('div', { class: 'f-head' },
      h('code', { class: 'f-rule' }, f.rule),
      h('span', { class: `sev sev-${f.severity}` }, f.severity),
      badge(f.action, 'badge-sm')),
    h('p', { class: 'f-msg' }, f.message))));
}

function deobBlock(layers, payloads, before, after) {
  const out = [];
  const used = layers.filter((l) => l.count > 0);
  if (!used.length && !payloads.length) return [h('p', { class: 'muted' }, 'No obfuscation layers found.')];
  out.push(h('ol', { class: 'layers' }, used.map((l) => h('li', {}, h('span', {}, l.label), h('span', { class: 'num' }, String(l.count))))));
  if (before !== undefined && after !== undefined && before !== after) {
    out.push(h('div', { class: 'diff' }, h('div', {}, h('h4', {}, 'As written'), pre(before)), h('div', {}, h('h4', {}, 'As decoded'), pre(after))));
  }
  for (const p of payloads) out.push(h('div', { class: 'payload' }, h('h4', {}, `Hidden ${p.kind} payload`), pre(p.decoded, 'code-hot')));
  return out;
}

function renderInspector(run) {
  const body = $('#insp-body');
  const id = state.selectedId;
  const isSink = id && id.endsWith('-sink');
  const node = run.nodes.find((n) => n.id === (isSink ? id.replace(/-sink$/, '') : id));
  if (!node) {
    body.replaceChildren(h('p', { class: 'muted' }, 'Select a node in the graph to see its lineage and the rules it matched.'));
    return;
  }
  const parts = [];
  if (isSink) {
    const spec = TOOL_CATALOG[node.tool];
    parts.push(h('p', { class: 'insp-title' }, `Effect of ${node.tool}`));
    parts.push(badge(node.decision, 'badge-lg'));
    parts.push(h('p', {}, node.decision === 'deny' || node.decision === 'require_approval'
      ? `The firewall stopped this call before it reached the ${spec ? spec.effect : 'target'} boundary.`
      : `This call reached the ${spec ? spec.effect : 'target'} boundary.`));
    parts.push(h('button', { type: 'button', class: 'btn', onclick: () => selectNode(node.id) }, `Inspect ${node.tool} call`));
  } else if (node.kind === 'user') {
    parts.push(h('p', { class: 'insp-title' }, node.label), badge('trusted'));
    parts.push(section('Instruction', pre(node.text)));
    parts.push(h('p', { class: 'muted' }, 'Values that appear here count as endorsed by the user and do not taint tool arguments.'));
  } else if (node.kind === 'source') {
    parts.push(h('p', { class: 'insp-title' }, `${node.label}, ${node.origin}`), badge(node.status));
    parts.push(meter(node.injection.score * 100, 'Injection'));
    parts.push(section('Injection signals', node.injection.hits.length
      ? h('ul', { class: 'hits' }, node.injection.hits.map((hit) => h('li', {}, h('strong', {}, hit.label), h('code', { class: 'excerpt' }, hit.excerpt))))
      : h('p', { class: 'muted' }, 'No injection signals.')));
    parts.push(section('De-obfuscation', ...deobBlock(node.deob.layers, node.deob.payloads, node.text, node.deob.text)));
    parts.push(section('Raw content', pre(node.text)));
  } else if (node.kind === 'planner') {
    parts.push(h('p', { class: 'insp-title' }, 'Planner'), badge(node.status));
    parts.push(section('Plan', pre(node.text)));
    const sources = node.taint.map((t) => run.nodes.find((n) => n.id === t)).filter(Boolean);
    parts.push(section('Context taint', sources.length
      ? h('ul', { class: 'lineage' }, sources.map((s) => h('li', {}, icon(STATUS_ICON[s.status], `ico s-${s.status}`), `${s.label} (${s.origin})`)))
      : h('p', { class: 'muted' }, 'Planned only from trusted or internal input.')));
  } else {
    parts.push(h('p', { class: 'insp-title' }, node.tool), h('div', { class: 'insp-row' }, badge(node.decision, 'badge-lg'), meter(node.risk)));
    parts.push(section('Arguments', pre(JSON.stringify(node.args, null, 2))));
    parts.push(section('Matched rules', findingsTable(node.findings)));
    const lineage = Object.entries(node.provenance || {});
    parts.push(section('Taint lineage', lineage.length
      ? h('ul', { class: 'lineage' }, lineage.map(([arg, p]) => h('li', {},
        h('code', {}, arg), p.endorsed ? ' endorsed by the user, also seen in ' : ' copied from ',
        p.sources.map((s) => `${s.origin} (${s.how})`).join(', '),
        h('code', { class: 'excerpt' }, p.sources[0].excerpt))))
      : h('p', { class: 'muted' }, 'No argument value traces back to untrusted content.')));
    const deobArgs = Object.entries(node.argDeob || {});
    if (deobArgs.length) {
      for (const [arg, d] of deobArgs) parts.push(section(`Decoded ${arg}`, ...deobBlock(d.layers, d.payloads, d.before, d.after)));
    }
  }
  body.replaceChildren(...parts);
}

// ---------- playback ----------

function stopPlay() {
  if (state.playing) clearInterval(state.playing);
  state.playing = null;
}

function stepTo(n) {
  const run = analysisFor(state.scenarioId);
  const total = run.nodes.length;
  state.step = Math.max(1, Math.min(total, n));
  state.selectedId = run.nodes[state.step - 1].id;
  if (state.step >= total) {
    stopPlay();
  }
  render();
}

function initTransport() {
  $('#step-prev').addEventListener('click', () => { stopPlay(); stepTo((state.step ?? 2) - 1); });
  $('#step-next').addEventListener('click', () => { stopPlay(); stepTo((state.step ?? 0) + 1); });
  $('#step-reset').addEventListener('click', () => { stopPlay(); state.step = null; render(); });
  $('#step-play').addEventListener('click', () => {
    if (state.playing) {
      stopPlay();
      render();
      return;
    }
    const run = analysisFor(state.scenarioId);
    if (state.step == null || state.step >= run.nodes.length) state.step = 0;
    state.playing = setInterval(() => stepTo((state.step ?? 0) + 1), reduceMotion.matches ? 1400 : 950);
    stepTo((state.step ?? 0) + 1);
  });
}

// ---------- playground ----------

const pg = { timer: null };

const FUZZ = {
  base64: (t) => `<span style="display:none">${btoa(String.fromCharCode(...new TextEncoder().encode(t)))}</span>`,
  zerowidth: (t) => t.replace(/([A-Za-z])(?=[A-Za-z])/g, `$1${String.fromCodePoint(0x200b)}`),
  homoglyph: (t) => t.replace(/[aeopc]/g, (c) => String.fromCodePoint({ a: 0x0430, e: 0x0435, o: 0x043e, p: 0x0440, c: 0x0441 }[c])),
  percent: (t) => t.replace(/[^\s]/g, (c) => [...new TextEncoder().encode(c)].map((b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join('')),
  entities: (t) => [...t].map((c) => (/[A-Za-z]/.test(c) ? `&#${c.codePointAt(0)};` : c)).join('')
};

function fillPlayground(id) {
  const s = getScenario(id);
  const user = s.nodes.find((n) => n.kind === 'user' && n.label === 'User prompt') || s.nodes.find((n) => n.kind === 'user');
  const src = s.nodes.find((n) => n.kind === 'source');
  const tool = s.nodes.find((n) => n.kind === 'tool' && n.truth === 'malicious') || s.nodes.find((n) => n.kind === 'tool');
  $('#pg-user').value = user ? user.text : '';
  $('#pg-source').value = src ? src.text : '';
  $('#pg-origin').value = src && [...$('#pg-origin').options].some((o) => o.value === src.origin) ? src.origin : 'web page';
  $('#pg-trust').value = src && src.trust === 'internal' ? 'internal' : 'untrusted';
  $('#pg-tool').value = tool.tool;
  $('#pg-args').value = JSON.stringify(tool.args, null, 2);
}

function playgroundScenario() {
  let args;
  let argsError = '';
  try {
    args = JSON.parse($('#pg-args').value);
  } catch (e) {
    argsError = `Arguments are not valid JSON (${e.message}). The guard fails closed on unparsable arguments.`;
    args = $('#pg-args').value;
  }
  const nodes = [{ id: 'u1', kind: 'user', label: 'User prompt', text: $('#pg-user').value }];
  const text = $('#pg-source').value;
  if (text.trim()) nodes.push({ id: 's1', kind: 'source', label: 'Your payload', origin: $('#pg-origin').value, trust: $('#pg-trust').value, text });
  nodes.push({ id: 'p1', kind: 'planner', label: 'Planner', text: 'Act on the prompt and the content.', from: nodes.map((n) => n.id) });
  nodes.push({ id: 't1', kind: 'tool', tool: $('#pg-tool').value, args, from: ['p1'], truth: 'malicious' });
  return { scenario: { id: 'playground', label: 'attack', title: 'Playground', category: 'Custom', summary: '', nodes }, argsError };
}

function renderPlayground() {
  const { scenario, argsError } = playgroundScenario();
  $('#pg-args-err').textContent = argsError;
  $('#pg-args').setAttribute('aria-invalid', argsError ? 'true' : 'false');
  const run = analyzeScenario(scenario, activePolicy());
  const call = run.nodes.find((n) => n.id === 't1');
  const src = run.nodes.find((n) => n.id === 's1');
  $('#pg-verdict').replaceChildren(
    h('h2', {}, 'Firewall verdict'),
    h('div', { class: 'insp-row' }, badge(call.decision, 'badge-lg'), meter(call.risk)),
    h('p', { class: 'pg-policy' }, `Policy ${LABELS[state.presetId]}`));
  renderGraph($('#pg-graph'), run, { interactive: false });
  const parts = [h('h3', {}, 'Matched rules'), findingsTable(call.findings)];
  const lineage = Object.entries(call.provenance || {});
  parts.push(h('h3', {}, 'Taint lineage'));
  parts.push(lineage.length
    ? h('ul', { class: 'lineage' }, lineage.map(([arg, p]) => h('li', {}, h('code', {}, arg), p.endorsed ? ' endorsed by the user' : ` copied from ${p.sources.map((s) => `${s.origin} (${s.how})`).join(', ')}`)))
    : h('p', { class: 'muted' }, 'No argument traces back to the untrusted content.'));
  if (src) {
    parts.push(h('h3', {}, 'Payload analysis'), meter(src.injection.score * 100, 'Injection'));
    if (src.injection.hits.length) parts.push(h('ul', { class: 'hits' }, src.injection.hits.map((hit) => h('li', {}, h('strong', {}, hit.label), h('code', { class: 'excerpt' }, hit.excerpt)))));
    parts.push(...deobBlock(src.deob.layers, src.deob.payloads, src.text, src.deob.text));
  }
  $('#pg-detail').replaceChildren(...parts);
}

function schedulePlayground() {
  clearTimeout(pg.timer);
  pg.timer = setTimeout(renderPlayground, 90);
}

function initPlayground() {
  $('#pg-base').replaceChildren(...SCENARIOS.map((s) => h('option', { value: s.id }, s.title)));
  $('#pg-tool').replaceChildren(...Object.keys(TOOL_CATALOG).map((t) => h('option', { value: t }, t)));
  $('#pg-base').value = 'env-b64-exfil';
  fillPlayground('env-b64-exfil');
  $('#pg-base').addEventListener('change', (e) => { fillPlayground(e.target.value); renderPlayground(); });
  $('#pg-form').addEventListener('input', (e) => { if (e.target.id !== 'pg-base') schedulePlayground(); });
  $('#pg-form').addEventListener('submit', (e) => e.preventDefault());
  $('#pg-tool').addEventListener('change', () => {
    const tool = $('#pg-tool').value;
    const template = Object.fromEntries(Object.keys(TOOL_CATALOG[tool].args).map((k) => [k, '']));
    $('#pg-args').value = JSON.stringify(template, null, 2);
    renderPlayground();
  });
  for (const btn of document.querySelectorAll('[data-fuzz]')) {
    btn.addEventListener('click', () => {
      const ta = $('#pg-source');
      ta.value = FUZZ[btn.dataset.fuzz](ta.value);
      renderPlayground();
    });
  }
}

// ---------- benchmark ----------

function renderBenchmark() {
  const bench = benchmarks();
  const keys = benchKeys();
  $('#metrics-table tbody').replaceChildren(...keys.map((k) => {
    const m = bench[k].callMetrics;
    return h('tr', { class: k === state.presetId ? 'is-active' : null },
      h('th', { scope: 'row' }, LABELS[k]),
      h('td', { class: 'num' }, `${m.tp}/${m.tp + m.fn}`),
      h('td', { class: 'num' }, `${m.fp}/${m.fp + m.tn}`),
      h('td', { class: 'num' }, m.precision.toFixed(2)),
      h('td', { class: 'num' }, m.recall.toFixed(2)),
      h('td', { class: 'num' }, h('strong', {}, m.f1.toFixed(2))),
      h('td', { class: 'num' }, `${(m.fpr * 100).toFixed(0)}%`));
  }));
  $('#matrix-table thead').replaceChildren(h('tr', {},
    h('th', { scope: 'col' }, 'Scenario'), h('th', { scope: 'col' }, 'Call'), h('th', { scope: 'col' }, 'Truth'),
    ...keys.map((k) => h('th', { scope: 'col' }, LABELS[k]))));
  const rows = [];
  for (const s of SCENARIOS) {
    const calls = bench[keys[0]].calls.filter((c) => c.scenario === s.id);
    calls.forEach((c, i) => {
      const cells = [];
      if (i === 0) cells.push(h('th', { scope: 'rowgroup', rowspan: calls.length, class: 'mx-scn' }, s.title));
      cells.push(h('td', {}, h('button', { type: 'button', class: 'linkish', onclick: () => { state.scenarioId = s.id; state.selectedId = c.nodeId; state.step = null; setTab('workbench'); } }, `${c.nodeId} ${c.tool}`)));
      cells.push(h('td', {}, h('span', { class: `truth t-${c.truth}` }, c.truth === 'malicious' ? 'Malicious' : 'Benign')));
      for (const k of keys) {
        const d = bench[k].calls.find((x) => x.scenario === s.id && x.nodeId === c.nodeId).decision;
        const intercept = d === 'deny' || d === 'require_approval';
        const correct = (c.truth === 'malicious') === intercept;
        cells.push(h('td', { class: `mx ${correct ? 'is-right' : 'is-wrong'}` }, badge(d, 'badge-sm'), correct ? null : h('span', { class: 'mx-miss' }, c.truth === 'malicious' ? 'missed' : 'false alarm')));
      }
      rows.push(h('tr', { class: i === 0 ? 'grp-start' : null }, ...cells));
    });
  }
  $('#matrix-table tbody').replaceChildren(...rows);
}

// ---------- policy editor ----------

function loadPolicyEditor() {
  $('#pol-json').value = stableStringify(activePolicy());
  $('#pol-status').replaceChildren(h('span', {}, `Editing ${LABELS[state.presetId]}. Apply to run it as the Custom policy.`));
  renderRulesTable();
}

function editorPolicy() {
  try {
    return JSON.parse($('#pol-json').value);
  } catch {
    return null;
  }
}

function renderRulesTable() {
  const p = editorPolicy();
  const rules = p && p.rules && typeof p.rules === 'object' ? p.rules : {};
  $('#rules-table tbody').replaceChildren(...Object.entries(RULES).map(([id, [sev, desc]]) => {
    const sel = h('select', { 'aria-label': `Action for ${id}`, 'data-rule': id, disabled: p ? null : true },
      ...['allow', 'log', 'require_approval', 'deny'].map((a) => h('option', { value: a, selected: (rules[id] || 'deny') === a ? true : null }, STATUS_TEXT[a])));
    return h('tr', {}, h('td', {}, h('code', {}, id), h('span', { class: 'rule-desc' }, desc)), h('td', {}, h('span', { class: `sev sev-${sev}` }, sev)), h('td', {}, sel));
  }));
}

function applyPolicy() {
  let parsed;
  try {
    parsed = JSON.parse($('#pol-json').value);
  } catch (e) {
    showPolicyErrors([`JSON parse error: ${e.message}`]);
    return false;
  }
  const v = validatePolicy(parsed);
  if (!v.ok) {
    showPolicyErrors(v.errors);
    return false;
  }
  if (Object.values(LABELS).includes(v.policy.name)) v.policy.name = `Custom from ${v.policy.name}`;
  state.custom = v.policy;
  state.presetId = 'custom';
  invalidateCustom();
  syncPresetRadios();
  $('#pol-status').replaceChildren(icon('i-allow', 'ico s-allow'), h('span', {}, `Applied "${v.policy.name}". Every view now runs this policy.`));
  updateDigest();
  render();
  return true;
}

function showPolicyErrors(errors) {
  $('#pol-status').replaceChildren(icon('i-deny', 'ico s-deny'),
    h('div', {}, h('p', {}, `Not applied. The last valid policy (${activePolicy().name}) stays active.`), h('ul', { class: 'errs' }, errors.slice(0, 8).map((e) => h('li', {}, e)))));
}

function download(name, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function exportGuard() {
  const sources = await loadGuardSources(async (name) => {
    const res = await fetch(`js/${name}`);
    if (!res.ok) throw new Error(`Could not load ${name}`);
    return res.text();
  });
  const out = await compileGuard(sources, activePolicy());
  download('shieldgraph-guard.mjs', out.code, 'text/javascript');
  $('#exp-status').textContent = `Downloaded shieldgraph-guard.mjs, ${Math.round(out.code.length / 1024)} KB, policy sha256 ${out.digest.slice(0, 12)}.`;
  return out;
}

function initPolicy() {
  loadPolicyEditor();
  $('#pol-apply').addEventListener('click', applyPolicy);
  $('#pol-reset').addEventListener('click', () => {
    if (state.presetId === 'custom') state.presetId = 'balanced';
    syncPresetRadios();
    loadPolicyEditor();
    render();
  });
  $('#pol-json').addEventListener('input', () => renderRulesTable());
  $('#rules-table').addEventListener('change', (e) => {
    const rule = e.target.dataset.rule;
    const p = editorPolicy();
    if (!rule || !p) return;
    p.rules = { ...(p.rules || {}), [rule]: e.target.value };
    $('#pol-json').value = stableStringify(p);
    applyPolicy();
  });
  $('#exp-guard').addEventListener('click', () => exportGuard().catch((e) => { $('#exp-status').textContent = `Export failed: ${e.message}`; }));
  $('#exp-policy').addEventListener('click', () => {
    download('shieldgraph-policy.json', `${stableStringify(activePolicy())}\n`, 'application/json');
    $('#exp-status').textContent = 'Downloaded shieldgraph-policy.json.';
  });
  $('#exp-print').addEventListener('click', printReport);
  $('#print-btn').addEventListener('click', printReport);
}

// ---------- report ----------

async function updateDigest() {
  state.digest = await sha256Hex(stableStringify(activePolicy()));
  buildReport();
}

function buildReport() {
  const bench = benchmarks();
  const generated = new Date().toLocaleDateString('en-CA');
  renderReport($('#report'), { policy: activePolicy(), digest: state.digest || '0'.repeat(64), bench, activeKey: state.presetId, labels: LABELS, generated });
}

function printReport() {
  buildReport();
  window.print();
}

// ---------- render ----------

function render() {
  syncPresetRadios();
  if (state.tab === 'workbench') {
    const run = analysisFor(state.scenarioId);
    if (!state.selectedId || !run.graph.nodes.some((g) => g.id === state.selectedId)) state.selectedId = defaultSelection(run);
    renderList();
    renderStage(run);
    renderInspector(run);
  } else if (state.tab === 'playground') {
    renderPlayground();
  } else if (state.tab === 'benchmark') {
    renderBenchmark();
  }
  writeHash();
}

function boot() {
  readHash();
  initTheme();
  initTabs();
  initPresets();
  initListKeys();
  initTransport();
  initPlayground();
  initPolicy();
  setTab(state.tab);
  updateDigest();
  window.addEventListener('resize', () => {
    clearTimeout(boot.rt);
    boot.rt = setTimeout(render, 120);
  });
  window.addEventListener('beforeprint', buildReport);
  document.documentElement.classList.add('is-ready');
  window.__shieldgraph = { state, exportGuard, applyPolicy, scoreInjection };
}

boot();
