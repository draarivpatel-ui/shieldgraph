// SVG renderer for the taint and tool-call flow graph. Built entirely with
// createElementNS and textContent, so no payload text is ever parsed as markup.

const NS = 'http://www.w3.org/2000/svg';

export const STATUS_TEXT = {
  allow: 'Allowed',
  log: 'Allowed, logged',
  require_approval: 'Needs approval',
  deny: 'Blocked',
  hostile: 'Hostile input',
  untrusted: 'Untrusted',
  internal: 'Internal',
  trusted: 'Trusted',
  contaminated: 'Contaminated',
  clean: 'Clean',
  neutral: ''
};

export const STATUS_ICON = {
  allow: 'i-allow', log: 'i-log', require_approval: 'i-approval', deny: 'i-deny',
  hostile: 'i-hostile', untrusted: 'i-untrusted', internal: 'i-internal', trusted: 'i-trusted',
  contaminated: 'i-plan', clean: 'i-plan'
};

const SHORT = { allow: 'Allowed', log: 'Logged', require_approval: 'Needs approval', deny: 'Blocked' };

const KIND_ICON = { user: 'i-user', source: 'i-doc', planner: 'i-plan', tool: 'i-tool', sink: 'i-sink' };
const COLS = ['input', 'planner', 'tool', 'sink'];

function el(tag, attrs = {}, parent) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) node.setAttribute(k, String(v));
  if (parent) parent.appendChild(node);
  return node;
}

function fit(text, max) {
  const s = String(text);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function statusOf(node) {
  if (node.kind === 'user') return 'trusted';
  return node.status || 'neutral';
}

/**
 * @param {HTMLElement} container
 * @param {object} analysis  result of analyzeScenario
 * @param {{step?:number|null, selectedId?:string|null, onSelect?:Function, vertical?:boolean, interactive?:boolean}} opts
 */
export function renderGraph(container, analysis, opts = {}) {
  const hadFocus = container.contains(document.activeElement) ? document.activeElement.getAttribute('data-id') : null;
  const vertical = opts.vertical ?? container.clientWidth < 640;
  const interactive = opts.interactive !== false;
  const order = analysis.nodes.map((n) => n.id);
  const stepLimit = opts.step == null ? order.length : opts.step;
  const visible = new Set(order.slice(0, stepLimit));
  for (const n of analysis.nodes) if (n.kind === 'tool' && visible.has(n.id)) visible.add(`${n.id}-sink`);
  const current = opts.step == null ? null : order[stepLimit - 1];
  const byId = new Map(analysis.nodes.map((n) => [n.id, n]));

  const W = vertical ? 128 : 168;
  const H = 58;
  const gapX = vertical ? 12 : 46;
  const gapY = vertical ? 46 : 16;
  const pad = 14;
  const colNodes = Object.fromEntries(COLS.map((c) => [c, analysis.graph.nodes.filter((g) => g.col === c)]));
  const maxRows = Math.max(...COLS.map((c) => colNodes[c].length));
  const pos = new Map();
  let width;
  let height;
  if (!vertical) {
    width = pad * 2 + COLS.length * W + (COLS.length - 1) * gapX;
    height = pad * 2 + maxRows * H + (maxRows - 1) * gapY + 18;
    COLS.forEach((c, ci) => {
      const list = colNodes[c];
      const colH = list.length * H + (list.length - 1) * gapY;
      const top = pad + 18 + ((height - pad * 2 - 18) - colH) / 2;
      list.forEach((g, ri) => pos.set(g.id, { x: pad + ci * (W + gapX), y: top + ri * (H + gapY), col: ci }));
    });
  } else {
    width = pad * 2 + maxRows * W + (maxRows - 1) * gapX;
    height = pad * 2 + COLS.length * H + (COLS.length - 1) * gapY;
    COLS.forEach((c, ci) => {
      const list = colNodes[c];
      const rowW = list.length * W + (list.length - 1) * gapX;
      const left = (width - rowW) / 2;
      list.forEach((g, ri) => pos.set(g.id, { x: left + ri * (W + gapX), y: pad + ci * (H + gapY), col: ci }));
    });
  }

  const svg = el('svg', { viewBox: `0 0 ${width} ${height}`, class: `gsvg${vertical ? ' is-vertical' : ''}`, role: 'presentation' });
  svg.style.aspectRatio = `${width} / ${height}`;
  const defs = el('defs', {}, svg);
  for (const kind of ['flow', 'taint', 'effect']) {
    const m = el('marker', { id: `mk-${kind}-${container.id}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse', class: `mk mk-${kind}` }, defs);
    el('path', { d: 'M0 0L10 5L0 10z' }, m);
  }
  const mb = el('marker', { id: `mk-blocked-${container.id}`, viewBox: '0 0 10 10', refX: 5, refY: 5, markerWidth: 8, markerHeight: 8, orient: 'auto', class: 'mk mk-blocked' }, defs);
  el('path', { d: 'M5 0V10', 'stroke-width': 2.6 }, mb);

  if (!vertical) {
    const heads = ['Inputs', 'Planner', 'Tool calls', 'Effects'];
    heads.forEach((t, i) => {
      const tx = el('text', { x: pad + i * (W + gapX), y: pad + 6, class: 'gcol' }, svg);
      tx.textContent = t;
    });
  }

  const edgeLayer = el('g', { class: 'gedges' }, svg);
  const nodeLayer = el('g', { class: 'gnodes' }, svg);

  for (const e of analysis.graph.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    let d;
    if (!vertical) {
      if (a.col === b.col) {
        const x = a.x + W;
        d = `M${x} ${a.y + H / 2} C${x + 34} ${a.y + H / 2} ${x + 34} ${b.y + H / 2} ${x} ${b.y + H / 2}`;
      } else {
        const x1 = a.x + W;
        const y1 = a.y + H / 2 + (e.type === 'taint' ? 7 : 0);
        const x2 = b.x - 2;
        const y2 = b.y + H / 2 + (e.type === 'taint' ? 7 : 0);
        const mid = (x2 - x1) / 2;
        d = `M${x1} ${y1} C${x1 + mid} ${y1} ${x2 - mid} ${y2} ${x2} ${y2}`;
      }
    } else if (a.col === b.col) {
      const y = a.y + H;
      d = `M${a.x + W / 2} ${y} C${a.x + W / 2} ${y + 26} ${b.x + W / 2} ${y + 26} ${b.x + W / 2} ${b.y + H}`;
    } else {
      const x1 = a.x + W / 2 + (e.type === 'taint' ? 10 : 0);
      const y1 = a.y + H;
      const x2 = b.x + W / 2 + (e.type === 'taint' ? 10 : 0);
      const y2 = b.y - 2;
      const mid = (y2 - y1) / 2;
      d = `M${x1} ${y1} C${x1} ${y1 + mid} ${x2} ${y2 - mid} ${x2} ${y2}`;
    }
    const shown = visible.has(e.from) && visible.has(e.to);
    const decisionClass = e.decision ? ` d-${e.decision}` : '';
    const path = el('path', { d, class: `ge ge-${e.type}${decisionClass}${shown ? '' : ' is-future'}${shown && (e.to === current || e.to === `${current}-sink`) ? ' is-new' : ''}` }, edgeLayer);
    path.setAttribute('marker-end', `url(#mk-${e.type === 'blocked' ? 'blocked' : e.type}-${container.id})`);
  }

  for (const g of analysis.graph.nodes) {
    const p = pos.get(g.id);
    const node = g.kind === 'sink' ? byId.get(g.parent) : byId.get(g.id);
    const status = g.kind === 'sink' ? (node.decision === 'deny' || node.decision === 'require_approval' ? 'stopped' : 'reached') : statusOf(node);
    const decisionStatus = g.kind === 'sink' ? node.decision : status;
    const shown = visible.has(g.id);
    const selected = opts.selectedId === g.id;
    const grp = el('g', {
      class: `gn gn-${g.kind} s-${decisionStatus}${shown ? '' : ' is-future'}${selected ? ' is-selected' : ''}${g.id === current ? ' is-current' : ''}`,
      transform: `translate(${p.x} ${p.y})`,
      'data-id': g.id
    }, nodeLayer);
    const statusText = g.kind === 'sink'
      ? (status === 'stopped' ? 'Not reached' : 'Reached')
      : (STATUS_TEXT[status] || '');
    const title = g.kind === 'tool' ? node.tool : g.kind === 'sink' ? g.label : node.label;
    if (interactive) {
      grp.setAttribute('tabindex', shown ? '0' : '-1');
      grp.setAttribute('role', 'button');
      grp.setAttribute('aria-pressed', selected ? 'true' : 'false');
      grp.setAttribute('aria-label', `${title}${statusText ? `, ${statusText}` : ''}${shown ? '' : ', not yet reached in playback'}`);
    }
    el('rect', { class: 'gn-focus', x: -4, y: -4, width: W + 8, height: H + 8, rx: 10 }, grp);
    el('rect', { class: 'gn-box', x: 0, y: 0, width: W, height: H, rx: 7 }, grp);
    el('use', { href: `#${KIND_ICON[g.kind]}`, x: 9, y: 9, width: 17, height: 17, class: 'gn-kind' }, grp);
    const label = el('text', { x: 32, y: 22, class: 'gn-label' }, grp);
    label.textContent = fit(title, vertical ? 11 : 17);
    const iconId = g.kind === 'sink' ? STATUS_ICON[node.decision] : STATUS_ICON[status];
    if (iconId && g.kind !== 'planner') el('use', { href: `#${iconId}`, x: 9, y: 33, width: 14, height: 14, class: 'gn-sicon' }, grp);
    const sub = el('text', { x: g.kind === 'planner' ? 10 : 28, y: 44, class: 'gn-sub' }, grp);
    sub.textContent = fit(g.kind === 'tool' ? (vertical ? SHORT[node.decision] : `${SHORT[node.decision]}, risk ${node.risk}`) : statusText, vertical ? 15 : 24);
    if (g.kind === 'tool' && vertical) {
      // Risk stays visible in the narrow layout through the accessible name.
      grp.setAttribute('aria-label', `${grp.getAttribute('aria-label')}, risk ${node.risk}`);
    }
    if (interactive && opts.onSelect) {
      grp.addEventListener('click', () => opts.onSelect(g.id));
      grp.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          opts.onSelect(g.id);
        }
      });
    }
  }

  container.replaceChildren(svg);
  if (hadFocus) {
    const again = svg.querySelector(`[data-id="${CSS.escape(hadFocus)}"]`);
    if (again) again.focus({ preventScroll: true });
  }
  return { vertical, width, height };
}
