// Path canonicalization, workspace escape, sensitive file and persistence checks.
import { decodePercent, stripInvisible } from './deobfuscate.mjs';

export const SENSITIVE_PATTERNS = [
  [/(^|\/)\.env(\.[\w.-]+)?$/i, 'environment secrets file'],
  [/(^|\/)\.ssh(\/|$)/i, 'SSH keys directory'],
  [/(^|\/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i, 'SSH private key'],
  [/(^|\/)\.aws\/(credentials|config)$/i, 'AWS credentials'],
  [/(^|\/)\.config\/gcloud(\/|$)/i, 'Google Cloud credentials'],
  [/(^|\/)\.azure(\/|$)/i, 'Azure credentials'],
  [/(^|\/)\.kube\/config$/i, 'Kubernetes config'],
  [/(^|\/)\.docker\/config\.json$/i, 'Docker registry auth'],
  [/(^|\/)\.npmrc$/i, 'npm auth token file'],
  [/(^|\/)\.pypirc$/i, 'PyPI auth file'],
  [/(^|\/)\.netrc$/i, 'netrc credentials'],
  [/(^|\/)\.git-credentials$/i, 'git credential store'],
  [/(^|\/)\.config\/gh\/hosts\.ya?ml$/i, 'GitHub CLI token file'],
  [/(^|\/)\.gnupg(\/|$)/i, 'GPG keyring'],
  [/(^|\/)Library\/Keychains(\/|$)/i, 'macOS keychain'],
  [/(^|\/)\.password-store(\/|$)/i, 'pass password store'],
  [/^\/etc\/(shadow|gshadow|sudoers|master\.passwd)$/i, 'system password database'],
  [/^\/etc\/passwd$/i, 'system account list'],
  [/^\/proc\/[^/]+\/environ$/i, 'process environment'],
  [/(^|\/)[^/]*\.(pem|key|p12|pfx|keystore|jks)$/i, 'private key or keystore'],
  [/(^|\/)(credentials|secrets?)\.(json|ya?ml|toml)$/i, 'credentials file']
];

export const PERSISTENCE_PATTERNS = [
  [/(^|\/)\.(bash|zsh)rc$/i, 'shell startup file'],
  [/(^|\/)\.(bash_)?profile$/i, 'login profile'],
  [/(^|\/)\.zprofile$/i, 'login profile'],
  [/(^|\/)\.git\/hooks\//i, 'git hook (runs on every commit)'],
  [/(^|\/)\.git\/config$/i, 'git config (can set hook paths)'],
  [/(^|\/)\.husky\//i, 'husky git hook'],
  [/(^|\/)Library\/LaunchAgents\//i, 'macOS launch agent'],
  [/(^|\/)\.config\/autostart\//i, 'desktop autostart'],
  [/(^|\/)\.config\/systemd\//i, 'systemd user unit'],
  [/^\/etc\/(cron|systemd|init\.d|profile\.d)/i, 'system startup or cron'],
  [/(^|\/)crontab$/i, 'cron table'],
  [/(^|\/)\.vscode\/(tasks|settings)\.json$/i, 'editor auto-run task'],
  [/(^|\/)\.github\/workflows\//i, 'CI workflow (runs with repo secrets)']
];

export const SYMLINK_ESCAPES = [
  [/^\/proc\/(self|\d+)\/(root|cwd|fd)(\/|$)/i, 'procfs link escape'],
  [/^\/dev\/fd\//i, 'file descriptor link'],
  [/(^|\/)\.\.\.+(\/|$)/, 'dot-run segment']
];

/**
 * Canonicalizes a path the way a POSIX resolver would, without touching disk.
 * @returns {{input:string, decoded:string, resolved:string, traversal:boolean, escapes:boolean, encoded:boolean}}
 */
export function canonicalizePath(input, options = {}) {
  const workspace = (options.workspaceRoot || '/workspace').replace(/\/+$/, '') || '/';
  const home = (options.homeDir || '/home/dev').replace(/\/+$/, '');
  const raw = String(input ?? '');
  const invisible = stripInvisible(raw).text;
  const decodedStep = decodePercent(invisible);
  let decoded = decodedStep.text.replace(/\\/g, '/').replace(/\0.*$/s, '');
  const encoded = decodedStep.count > 0;
  decoded = decoded.replace(/^file:\/\//i, '');
  if (decoded === '~' || decoded.startsWith('~/')) decoded = home + decoded.slice(1);
  decoded = decoded.replace(/^\$\{?HOME\}?(?=\/|$)/, home);
  const absolute = decoded.startsWith('/') ? decoded : `${workspace}/${decoded}`;
  const stack = [];
  let traversal = false;
  for (const segment of absolute.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      traversal = true;
      stack.pop();
      continue;
    }
    stack.push(segment);
  }
  const resolved = `/${stack.join('/')}`;
  const inside = workspace === '/' || resolved === workspace || resolved.startsWith(`${workspace}/`);
  return { input: raw, decoded, resolved, traversal, escapes: !inside, encoded };
}

export function analyzePath(input, options = {}) {
  const findings = [];
  const c = canonicalizePath(input, options);
  const mode = options.mode || 'read';
  if (c.traversal && c.escapes) {
    findings.push({ rule: 'pathTraversal', severity: 'critical', message: `"${c.input}" climbs out of the workspace to ${c.resolved}.` });
  } else if (c.escapes) {
    findings.push({ rule: 'outsideWorkspace', severity: 'medium', message: `${c.resolved} is outside the workspace root.` });
  }
  if (c.encoded && c.traversal) {
    findings.push({ rule: 'pathTraversal', severity: 'critical', message: 'Traversal segments were hidden with percent-encoding.' });
  }
  for (const [pattern, label] of SENSITIVE_PATTERNS) {
    if (pattern.test(c.resolved)) {
      findings.push({ rule: 'sensitivePath', severity: 'critical', message: `${c.resolved} is a protected file (${label}).` });
      break;
    }
  }
  if (mode === 'write') {
    for (const [pattern, label] of PERSISTENCE_PATTERNS) {
      if (pattern.test(c.resolved)) {
        findings.push({ rule: 'persistencePath', severity: 'high', message: `Writing ${c.resolved} touches a ${label}.` });
        break;
      }
    }
  }
  for (const [pattern, label] of SYMLINK_ESCAPES) {
    if (pattern.test(c.decoded) || pattern.test(c.resolved)) {
      findings.push({ rule: 'pathTraversal', severity: 'high', message: `${c.decoded} uses a ${label}.` });
      break;
    }
  }
  return { ...c, findings };
}
