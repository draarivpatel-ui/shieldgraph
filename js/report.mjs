// Builds the one-page printable Security Audit Sheet from live results.
import { RULES } from './policy.mjs';
import { STATUS_TEXT } from './graph.mjs';

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

const pct = (x) => `${(x * 100).toFixed(0)}%`;

/**
 * @param {HTMLElement} target
 * @param {{policy:object, digest:string, bench:Record<string,object>, activeKey:string, labels:Record<string,string>, generated:string}} data
 */
export function renderReport(target, data) {
  const active = data.bench[data.activeKey];
  const counts = { deny: 0, require_approval: 0, log: 0, allow: 0 };
  for (const id of Object.keys(RULES)) counts[data.policy.rules[id]] = (counts[data.policy.rules[id]] || 0) + 1;

  const metricRows = Object.entries(data.bench).map(([key, b]) => {
    const m = b.callMetrics;
    return h('tr', { class: key === data.activeKey ? 'is-active' : null },
      h('th', { scope: 'row' }, data.labels[key]),
      h('td', {}, `${m.tp}/${m.tp + m.fn}`),
      h('td', {}, `${m.fp}/${m.fp + m.tn}`),
      h('td', {}, m.precision.toFixed(2)),
      h('td', {}, m.recall.toFixed(2)),
      h('td', {}, m.f1.toFixed(2)),
      h('td', {}, pct(m.fpr)));
  });

  const scenarioRows = active.runs.map((r) => {
    const deciding = r.calls.flatMap((c) => c.findings).find((f) => f.action === 'deny' || f.action === 'require_approval');
    const malicious = r.calls.filter((c) => c.truth === 'malicious');
    const caught = malicious.filter((c) => c.decision === 'deny' || c.decision === 'require_approval').length;
    const outcome = r.scenario.label === 'attack'
      ? `${caught}/${malicious.length} malicious stopped`
      : (r.calls.some((c) => c.decision === 'deny' || c.decision === 'require_approval') ? 'Interrupted' : 'Ran clean');
    return h('tr', {},
      h('td', {}, r.scenario.title),
      h('td', {}, r.scenario.label === 'attack' ? 'Attack' : 'Benign'),
      h('td', {}, STATUS_TEXT[r.verdict]),
      h('td', { class: 'num' }, String(r.risk)),
      h('td', {}, outcome),
      h('td', {}, deciding ? deciding.rule : 'none'));
  });

  target.replaceChildren(
    h('header', { class: 'rp-head' },
      h('h1', {}, 'ShieldGraph Security Audit'),
      h('dl', { class: 'rp-meta' },
        h('dt', {}, 'Policy'), h('dd', {}, data.policy.name),
        h('dt', {}, 'SHA-256'), h('dd', { class: 'mono' }, `${data.digest.slice(0, 16)}...${data.digest.slice(-8)}`),
        h('dt', {}, 'Generated'), h('dd', {}, data.generated),
        h('dt', {}, 'Corpus'), h('dd', {}, `${active.runs.length} scenarios, ${active.calls.length} tool calls`))),
    h('section', {},
      h('h2', {}, 'Detection by policy'),
      h('table', { class: 'rp-table' },
        h('thead', {}, h('tr', {}, ...['Policy', 'Caught', 'Benign hit', 'Precision', 'Recall', 'F1', 'FPR'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, metricRows)),
      h('p', { class: 'rp-note' }, 'A call counts as intercepted when it is blocked or held for human approval.')),
    h('section', {},
      h('h2', {}, `Scenario results under ${data.policy.name}`),
      h('table', { class: 'rp-table' },
        h('thead', {}, h('tr', {}, ...['Scenario', 'Truth', 'Verdict', 'Risk', 'Outcome', 'Deciding rule'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', {}, scenarioRows))),
    h('section', { class: 'rp-cols' },
      h('div', {},
        h('h2', {}, 'Rule set'),
        h('p', {}, `${counts.deny} rules block, ${counts.require_approval} hold for approval, ${counts.log} log, ${counts.allow} allow. Unknown tools and guard errors always fail closed.`),
        h('p', {}, `Workspace ${data.policy.workspaceRoot}. Internal content ${data.policy.trustInternal ? 'trusted' : 'treated as untrusted'}. Injection threshold ${data.policy.injectionThreshold}.`)),
      h('div', {},
        h('h2', {}, 'Egress allowlist'),
        h('p', { class: 'mono' }, data.policy.egressAllow.join(', ') || 'empty'))),
    h('footer', { class: 'rp-foot' },
      h('p', {}, 'Scope. Deterministic static and taint analysis of recorded agent traces. It does not observe DNS resolution, HTTP redirects, real symlinks or model reasoning. Scenarios are authored test cases with synthetic data, not production telemetry.')));
}
