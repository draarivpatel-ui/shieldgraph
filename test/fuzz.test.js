import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzePath, canonicalizePath } from '../js/pathguard.mjs';
import fc from 'fast-check';
import { deobfuscate } from '../js/deobfuscate.mjs';
import { validatePolicy } from '../js/policy.mjs';

const PATH_OPTIONS = Object.freeze({ workspaceRoot: '/workspace', homeDir: '/home/dev' });

test('fast-check canonicalized paths stay normalized and containment is truthful', () => {
  const segment = fc.constantFrom(
    'safe', 'a', '..', '.', '', '%2e%2e', '%2E%2E', '%2f', '..%2f',
    'x y', 'é', '\\', '%00', 'nested'
  );
  const input = fc.tuple(
    fc.constantFrom('', '/', '~/', '$HOME/'),
    fc.array(segment, { maxLength: 8 })
  ).map(([prefix, parts]) => prefix + parts.join('/'));
  fc.assert(fc.property(input, (value) => {
    const first = canonicalizePath(value, PATH_OPTIONS);
    const second = canonicalizePath(value, PATH_OPTIONS);
    assert.deepEqual(first, second);
    assert.ok(first.resolved.startsWith('/'));
    assert.equal(first.resolved.includes('\\'), false);
    assert.equal(first.resolved.includes('\0'), false);
    if (first.resolved !== '/') {
      const segments = first.resolved.split('/').slice(1);
      assert.equal(segments.includes(''), false);
      assert.equal(segments.includes('.'), false);
      assert.equal(segments.includes('..'), false);
    }
    if (!first.escapes) {
      assert.ok(first.resolved === '/workspace' || first.resolved.startsWith('/workspace/'),
        `contained path resolved outside the workspace: ${first.resolved}`);
    }
  }), { seed: 44920, numRuns: 240 });
});

test('fast-check percent-encoded parent traversal is always critical', () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 5 }),
    fc.integer({ min: 1, max: 5 }),
    (depth, extraParents) => {
      const input = '/workspace/' + 'a/'.repeat(depth) + '%2e%2e/'.repeat(depth + extraParents) + 'secret.txt';
      const result = analyzePath(input, PATH_OPTIONS);
      assert.equal(result.traversal, true, input);
      assert.equal(result.escapes, true, input);
      assert.ok(result.findings.some((finding) => finding.rule === 'pathTraversal' && finding.severity === 'critical'));
    }
  ), { seed: 0x2E2E, numRuns: 100 });
});

test('fast-check deobfuscation is deterministic and preserves its layer accounting', () => {
  const unit = fc.constantFrom(
    'a', 'move', '%2e%2e', '%41', '%252e', '&lt;', '&#x41;', '&amp;',
    '\u200b', '\u202e', 'aWdub3Jl', '414243', 'é', 'ａ', ' '
  );
  const input = fc.string({ unit, minLength: 0, maxLength: 12 });
  fc.assert(fc.property(input, (value) => {
    const first = deobfuscate(value);
    const second = deobfuscate(value);
    assert.deepEqual(
      { text: first.text, analysisText: first.analysisText, changed: first.changed, payloads: first.payloads },
      { text: second.text, analysisText: second.analysisText, changed: second.changed, payloads: second.payloads }
    );
    assert.equal(typeof first.text, 'string');
    assert.ok(first.analysisText.startsWith(first.text));
    assert.deepEqual(first.changed, first.layers.filter((layer) => layer.count > 0).map((layer) => layer.id));
  }), { seed: 0xDE0B, numRuns: 140 });
});

test('fast-check policy validation rejects unknown keys and keeps fail-closed rules denied', () => {
  const known = new Set(['name', 'version', 'defaultAction', 'workspaceRoot', 'homeDir', 'trustInternal',
    'injectionThreshold', 'egressAllow', 'protectedBrands', 'tools', 'rules', '__proto__', 'constructor', 'prototype']);
  const unknownKey = fc.string({ minLength: 1, maxLength: 14 }).filter((value) => !known.has(value));
  const action = fc.constantFrom('allow', 'log', 'require_approval', 'deny');
  fc.assert(fc.property(unknownKey, action, (key, attempted) => {
    const failClosedRules = { unknownTool: attempted, guardError: attempted, badArgs: attempted, budgetExceeded: attempted };
    const withUnknown = validatePolicy({ version: 1, rules: failClosedRules, [key]: true });
    assert.equal(withUnknown.ok, false);
    assert.equal(withUnknown.policy, null);
    const valid = validatePolicy({ version: 1, rules: failClosedRules });
    assert.equal(valid.ok, true, valid.errors.join('; '));
    for (const id of ['unknownTool', 'guardError', 'badArgs', 'budgetExceeded']) {
      assert.equal(valid.policy.rules[id], 'deny');
    }
  }), { seed: 0xFA11, numRuns: 120 });
});
