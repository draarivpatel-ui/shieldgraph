// A small POSIX shell lexer plus danger classifier. It splits a command line
// into simple commands the way sh would, honoring quotes and escapes.

const INTERPRETERS = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'python', 'python3', 'node', 'perl', 'ruby', 'php', 'pwsh', 'powershell', 'osascript'];
const NETWORK_TOOLS = ['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'nslookup', 'dig', 'host'];
const PRIVILEGE_TOOLS = ['sudo', 'su', 'doas', 'chmod', 'chown', 'setfacl', 'crontab', 'launchctl', 'systemctl'];
const DESTRUCTIVE = ['rm', 'mkfs', 'dd', 'shred', 'truncate'];

export function lexShell(command) {
  const src = String(command ?? '');
  const tokens = [];
  const features = new Set();
  let word = '';
  let hasWord = false;
  let quote = null;
  const flush = () => {
    if (hasWord) tokens.push({ type: 'word', value: word });
    word = '';
    hasWord = false;
  };
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    const next = src[i + 1];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else word += ch;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === '\\' && next !== undefined && '"\\$`'.includes(next)) {
        word += next;
        i += 1;
      } else {
        if (ch === '$' && next === '(') features.add('substitution');
        if (ch === '`') features.add('substitution');
        word += ch;
      }
      continue;
    }
    if (ch === '\\' && next !== undefined) {
      if (next === '\n') { i += 1; continue; }
      word += next;
      hasWord = true;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      hasWord = true;
      continue;
    }
    if (ch === '#' && !hasWord) {
      while (i < src.length && src[i] !== '\n') i += 1;
      i -= 1;
      continue;
    }
    if (/\s/.test(ch) && ch !== '\n') {
      flush();
      continue;
    }
    const three = src.slice(i, i + 3);
    const two = src.slice(i, i + 2);
    if (ch === '$' && next === '(') {
      features.add('substitution');
      word += '$(';
      hasWord = true;
      i += 1;
      continue;
    }
    if (ch === '`') {
      features.add('substitution');
      word += ch;
      hasWord = true;
      continue;
    }
    if (three === '<<<' || two === '<<') {
      flush();
      tokens.push({ type: 'op', value: three === '<<<' ? '<<<' : '<<' });
      features.add('redirect');
      i += (three === '<<<' ? 2 : 1);
      continue;
    }
    if (two === '&&' || two === '||' || two === '>>' || two === '|&' || two === '&>' || two === '>|') {
      flush();
      tokens.push({ type: 'op', value: two });
      features.add(two === '&&' || two === '||' ? 'chain' : two === '|&' ? 'pipe' : 'redirect');
      i += 1;
      continue;
    }
    if ((ch === '<' || ch === '>') && next === '(') {
      flush();
      features.add('substitution');
      tokens.push({ type: 'op', value: `${ch}(` });
      i += 1;
      continue;
    }
    if (ch === ';' || ch === '\n' || ch === '|' || ch === '&' || ch === '>' || ch === '<') {
      flush();
      tokens.push({ type: 'op', value: ch === '\n' ? ';' : ch });
      if (ch === ';' || ch === '\n') features.add('chain');
      else if (ch === '|') features.add('pipe');
      else if (ch === '&') features.add('background');
      else features.add('redirect');
      continue;
    }
    word += ch;
    hasWord = true;
  }
  flush();
  if (quote) features.add('unbalancedQuote');
  return { tokens, features: [...features] };
}

export function splitCommands(tokens) {
  const commands = [];
  let current = { argv: [], pipedFrom: false, redirects: [] };
  let pendingPipe = false;
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.type === 'word') {
      current.argv.push(t.value);
      continue;
    }
    if (['>', '>>', '<', '&>', '>|'].includes(t.value)) {
      const target = tokens[i + 1];
      if (target && target.type === 'word') {
        current.redirects.push({ op: t.value, target: target.value });
        i += 1;
      }
      continue;
    }
    if (current.argv.length) commands.push(current);
    pendingPipe = t.value === '|' || t.value === '|&';
    current = { argv: [], pipedFrom: pendingPipe, redirects: [] };
  }
  if (current.argv.length) commands.push(current);
  return commands;
}

function baseName(word) {
  const w = String(word).replace(/^.*\//, '');
  return w.toLowerCase();
}

function commandName(argv) {
  let i = 0;
  while (i < argv.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i]) || ['env', 'command', 'exec', 'nohup', 'time', 'xargs'].includes(baseName(argv[i])))) i += 1;
  return { name: baseName(argv[i] || ''), args: argv.slice(i + 1) };
}

/**
 * Lexes a command line and lists dangerous constructs.
 * @returns {{commands: object[], features: string[], findings: object[]}}
 */
export function analyzeShell(command) {
  const { tokens, features } = lexShell(command);
  const commands = splitCommands(tokens).map((c) => ({ ...c, ...commandName(c.argv) }));
  const findings = [];
  const add = (rule, severity, message) => findings.push({ rule, severity, message });
  const text = String(command ?? '');

  for (const c of commands) {
    const args = c.args.join(' ');
    if (c.pipedFrom && INTERPRETERS.includes(c.name)) add('pipeToShell', 'critical', `Output is piped straight into ${c.name}.`);
    if (NETWORK_TOOLS.includes(c.name)) add('networkTool', 'high', `${c.name} opens a network connection.`);
    if ((c.name === 'nc' || c.name === 'ncat' || c.name === 'netcat') && /(^|\s)-(e|c)\b/.test(args)) add('reverseShell', 'critical', `${c.name} -e binds a shell to a socket.`);
    if (PRIVILEGE_TOOLS.includes(c.name)) add('privilegeChange', 'high', `${c.name} changes privileges or schedules code.`);
    if (DESTRUCTIVE.includes(c.name)) {
      const recursive = /(^|\s)-[a-z]*r[a-z]*f|(^|\s)-[a-z]*f[a-z]*r|--recursive|--no-preserve-root/i.test(args);
      const broad = c.args.some((a) => a === '/' || a === '~' || a === '*' || a === '/*' || a === '$HOME' || a === '..');
      if (c.name !== 'rm' || recursive || broad) add('destructive', recursive && broad ? 'critical' : 'high', `${c.name} ${args}`.trim() + ' can destroy data.');
    }
    if (c.name === 'ln' && /(^|\s)-[a-z]*s/i.test(args)) add('symlinkCreate', 'high', 'ln -s can plant a link that escapes the workspace.');
    if (c.name === 'base64' && /(^|\s)(-d|--decode|-D)\b/.test(args)) add('decodeExec', 'high', 'base64 decoding inside a command often hides a payload.');
    if (INTERPRETERS.includes(c.name) && /(^|\s)-(c|e)\b/.test(args)) add('inlineInterpreter', 'medium', `${c.name} runs an inline script.`);
    if (c.name === 'eval') add('inlineInterpreter', 'high', 'eval executes a constructed string.');
    if (c.name === 'git' && /config\b.*core\.(hooksPath|sshCommand|pager|editor)/.test(args)) add('privilegeChange', 'high', 'git config redirects a code-executing setting.');
    for (const r of c.redirects) {
      if (/(^|\/)\.(bash|zsh)rc$|\.profile$|\.git\/hooks\/|crontab|LaunchAgents/.test(r.target)) add('persistenceWrite', 'high', `Redirect writes into ${r.target}.`);
      if (/^\/dev\/(tcp|udp)\//.test(r.target)) add('reverseShell', 'critical', `Redirect to ${r.target} opens a raw socket.`);
    }
  }
  if (/\/dev\/(tcp|udp)\//.test(text) && !findings.some((f) => f.rule === 'reverseShell')) add('reverseShell', 'critical', 'Command references /dev/tcp, a raw socket.');
  if (features.includes('substitution')) add('commandSubstitution', 'medium', 'Command substitution runs a nested command.');
  if (features.includes('unbalancedQuote')) add('unbalancedQuote', 'medium', 'Quotes are unbalanced, a common breakout sign.');
  return { commands, features, findings };
}
