import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const auditScript = path.join(root, 'tests', 'browser-audit.mjs');
const tmpRoot = fs.realpathSync(os.tmpdir());
const auditTempDirs = () => fs.readdirSync(tmpRoot).filter((name) => name.startsWith('shieldgraph-audit-'));

test('browser audit exits nonzero and removes its temp directory when Chrome cannot spawn', () => {
  const before = new Set(auditTempDirs());
  const missingChrome = path.join(tmpRoot, `missing-shieldgraph-chrome-${process.pid}`);
  const result = spawnSync(process.execPath, [auditScript], {
    env: { ...process.env, CHROME_BIN: missingChrome },
    encoding: 'utf8',
    timeout: 15000
  });
  const leaked = auditTempDirs().filter((name) => !before.has(name));
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, /Chrome failed to start|audit ran to completion/);
  assert.deepEqual(leaked, []);
});

test('browser audit removes its temp directory when port setup fails before Chrome starts', () => {
  const patchDir = fs.mkdtempSync(path.join(tmpRoot, 'shieldgraph-preload-'));
  try {
    const preload = path.join(patchDir, 'fail-port.cjs');
    fs.writeFileSync(preload, "const net = require('node:net');\nnet.createServer = function createServer() {\n  throw new Error('forced port allocation failure');\n};\n");
    const before = new Set(auditTempDirs());
    const nodeOptions = [process.env.NODE_OPTIONS, `--require ${preload}`].filter(Boolean).join(' ');
    const result = spawnSync(process.execPath, [auditScript], {
      env: { ...process.env, NODE_OPTIONS: nodeOptions },
      encoding: 'utf8',
      timeout: 15000
    });
    const leaked = auditTempDirs().filter((name) => !before.has(name));
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /forced port allocation failure/);
    assert.deepEqual(leaked, []);
  } finally {
    fs.rmSync(patchDir, { recursive: true, force: true, maxRetries: 10 });
  }
});
