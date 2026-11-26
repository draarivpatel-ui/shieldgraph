export function traceArgumentText(node, arg, value, outcome, formatValue) {
  const provenance = node && node.provenance && typeof node.provenance === 'object' ? node.provenance : null;
  const trace = provenance && Object.prototype.hasOwnProperty.call(provenance, arg) ? provenance[arg] : null;
  const sources = trace && Array.isArray(trace.sources) ? trace.sources : [];
  let source = 'no untrusted source match (origin not established)';
  if (sources.length) {
    const seen = sources.map((s) => `${s && s.origin ? s.origin : 'unknown source'} (${s && s.how ? s.how : 'match'})`).join(' or ');
    source = trace.endorsed ? `user-endorsed value also seen in ${seen}` : seen;
  }
  const findings = node && Array.isArray(node.findings) ? node.findings : [];
  const matched = findings.filter((f) => !f.arg || f.arg === arg).map((f) => f.rule);
  const rulesText = matched.length ? matched.join(', ') : 'no rule matched';
  const shown = formatValue(value);
  return `${source} -> ${arg}${shown ? ` "${shown}"` : ''} -> ${rulesText} -> ${outcome}`;
}
