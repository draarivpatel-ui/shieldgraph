// Compiles a policy into a standalone guard module from the command line.
//   node tools/build-guard.mjs                       Balanced preset -> shieldgraph-guard.mjs
//   node tools/build-guard.mjs zeroTrust out.mjs     another preset
//   node tools/build-guard.mjs my-policy.json        a policy manifest file
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileGuard, loadGuardSources } from '../js/compiler.mjs';
import { presetPolicy } from '../js/engine.mjs';
import { PRESETS, validatePolicy } from '../js/policy.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const [source = 'balanced', out = 'shieldgraph-guard.mjs'] = process.argv.slice(2);

let policy;
if (PRESETS[source]) {
  policy = presetPolicy(source);
} else {
  const v = validatePolicy(JSON.parse(fs.readFileSync(source, 'utf8')));
  if (!v.ok) {
    console.error(`Policy rejected\n  ${v.errors.join('\n  ')}`);
    process.exit(1);
  }
  policy = v.policy;
}
const sources = await loadGuardSources((name) => fs.readFileSync(path.join(root, 'js', name), 'utf8'));
const guard = await compileGuard(sources, policy);
fs.writeFileSync(out, guard.code);
console.log(`Wrote ${out} (${guard.code.length} bytes) for policy "${policy.name}", sha256 ${guard.digest}`);
