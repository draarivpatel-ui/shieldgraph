# ShieldGraph

ShieldGraph is a firewall and red-team workbench for the tool calls an AI agent makes. It replays an agent trace (user prompt, untrusted content, planner, tool calls, effects), checks arguments for untrusted text-match evidence, marks arguments without a match as `origin not established`, peels off the obfuscation attackers use, and decides whether each call is allowed, logged, held for a human, or blocked. The same decision code compiles into `shieldgraph-guard.mjs`, a zero-dependency middleware you can drop in front of a real agent's tool executor.

Everything runs in the browser. No API keys, no external requests or model calls, no build step, no dependencies. The browser fetches only same-origin static files, including the detector module sources needed to compile a guard export; guard and policy exports are generated locally as downloads.

![ShieldGraph workbench, light theme](docs/screenshots/desktop-workbench-light.png)

## Run it

```sh
node tools/serve.mjs          # then open http://127.0.0.1:8737/
```

Node.js 22 or newer is required for the tests, guard build and generated middleware runtime. Any static file server works for the page. ES modules do not load from `file://`, so open it over HTTP.

## What it does

- **Taint and provenance tracking.** String arguments are checked for verbatim, partial-copy and decoded matches against trusted and untrusted text. A value the user typed is endorsed. A value copied from a web page, email, README, PDF, webhook or tool output is tainted, and a tainted value reaching a privileged tool raises a finding. An argument with no untrusted text match is labeled `origin not established`, not proven safe. Endorsement matches whole tokens, so `a@client.example` is not endorsed by `ana@client.example`.
- **De-obfuscation pipeline.** Invisible characters and Unicode tag smuggling are stripped, HTML entities and multi-round percent-encoding (`%252e`) decoded, text folded with NFKC and a Cyrillic and Greek homoglyph map, and Base64, hex and `\x` payloads extracted when they decode to readable text. Binary results such as git SHAs and npm integrity hashes are rejected, so they do not cause false alarms.
- **SSRF and egress guard.** URLs go through the WHATWG parser, so decimal (`2852039166`), octal, hex and short-form IPv4 are normalized first and then flagged as obfuscated. Private, loopback, link-local, CGNAT, multicast and metadata ranges are blocked for IPv4 and IPv6, including IPv4-mapped and NAT64 addresses. Also caught are `allowed.com@evil.com` userinfo tricks, non-http schemes, punycode and ASCII lookalike hosts, secrets in query strings, and data encoded into DNS labels.
- **Path guard.** Paths are canonicalized without touching disk (`~`, `$HOME`, backslashes, NUL suffixes, encoded dot segments) and checked for workspace escape, credential files (`.env`, `~/.ssh`, `~/.aws/credentials`, keychains, the GitHub CLI token file and more), persistence targets (shell rc files, git hooks, launch agents, CI workflows) and procfs link escapes.
- **Shell analysis.** A small POSIX lexer splits commands the way `sh` would, honoring quotes, then flags pipe-to-interpreter, reverse shells, destructive commands, network tools, permission changes, symlink planting and decode-and-run chains. Wrappers do not hide a payload, because `sh -c` scripts and `$( )`, backtick and `<( )` substitutions are re-analyzed up to three levels deep, and every argument is checked as a path (so `head .env` is caught like `cat .env`). Shell operators that arrived inside untrusted text are treated as command injection.
- **Prompt-injection scoring.** Ten signal families (authority override, fake role markers, delimiter breakout, agent-addressed orders, secrecy requests, tool directives, exfiltration verbs, urgency, hidden carriers, markdown beacon templates) run on the decoded text and combine like independent probabilities.
- **Confused-deputy checks.** Email recipients and payment accounts must have been named by the user. A wire to an account that appears only in an inbound email is blocked.
- **Policy compiler.** Policies are JSON manifests with a per-tool action, argument length cap and call cap, plus an action for each of 41 rules. Validation rejects unknown keys, and any rule left out defaults to deny. Exports are the runnable guard, the policy JSON and a one-page printable audit sheet.

## Benchmark

The corpus has 14 authored scenarios, 10 attacks and 4 ordinary workflows, with 29 tool calls labeled by hand (15 malicious, 14 benign). A call counts as intercepted when it is blocked or held for approval. These numbers are recomputed live in the Benchmark view, and `tests/policy.test.mjs` fails if this table drifts from them.

| Policy | Malicious calls caught | Benign calls interrupted | Precision | Recall | F1 | False positive rate | Denied | Held for approval |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Permissive | 3/15 | 0/14 | 1.00 | 0.20 | 0.33 | 0% | 3 | 0 |
| Balanced | 15/15 | 0/14 | 1.00 | 1.00 | 1.00 | 0% | 14 | 1 |
| Zero-Trust | 15/15 | 8/14 | 0.65 | 1.00 | 0.79 | 57% | 21 | 2 |

Read the Balanced row with care. The scenarios and the detectors were written by the same person, so a perfect score on this set says the detectors cover these attack shapes, not that they generalize. No detector or policy source mentions a scenario id (a test enforces this), and `tests/policy.test.mjs` pins three attacks that Balanced misses today.

- Exfiltrating ordinary source code to an allowlisted host.
- A command assembled with `printf` so the network tool name never appears.
- DNS rebinding, where an outside hostname later resolves to a private address.

## Use the guard in an agent

Export `shieldgraph-guard.mjs` from the Policy view, or build one from the command line.

```sh
node tools/build-guard.mjs balanced shieldgraph-guard.mjs
node tools/build-guard.mjs my-policy.json
```

```js
import { createGuard } from './shieldgraph-guard.mjs';

const guard = createGuard({ approve: async (call, verdict) => askHuman(call, verdict) });
guard.addTrusted(userPrompt);                 // the user's own words
guard.addUntrusted(pageText, 'web page');     // anything fetched or received

// Every tool call goes through run(). Denied calls throw ShieldGraphBlocked,
// held calls wait for approve(), and results feed back into the context
// (secrets read from credential files are remembered and stopped on the way out).
// The executor also receives the exact frozen call snapshot as its second argument.
const out = await guard.run({ tool: 'shell_exec', args: { cmd } }, (args, frozenCall) => exec(args.cmd));
```

Tool results feed back into the context. Files read with `read_file` count as internal content, which the Balanced preset trusts, so pass third-party files (a cloned repo's README, a downloaded PDF) through `guard.addUntrusted` yourself.

The guard file is built by concatenating the exact detector modules the workbench runs, so the two cannot drift. A parity test imports the compiled guard for every preset and checks that it returns the same decision, risk and rule list as the engine for all 29 calls. Execution tests prove that allowed calls reach a mock executor, denied or rejected calls never do, held calls wait for the approval callback, and concurrent calls reserve per-tool quota before yielding.

## Scope and limits

ShieldGraph is deterministic static and taint analysis of recorded traces. It is honest about what that cannot see.

- It does not resolve DNS, follow HTTP redirects or inspect real symlinks on disk. A guard in production should pair it with a resolving egress proxy.
- It does not read model reasoning. Taint comes from string provenance, so a planner that paraphrases an attacker's instruction into fresh words is caught only by the sink-side rules.
- Injection scoring is pattern based. It is tuned to keep ordinary text ("ignore case differences", "user agent string") below threshold, and a determined attacker can write around it, which is why the sink rules carry most of the weight.
- The scenarios use synthetic data, reserved `.example` domains and TEST-NET addresses. There is no production telemetry and no claim of real-world deployment.
- Provenance matching and injection scoring are text heuristics, not cryptographic identity, sandboxing or OS-level authorization. `run()` is application-layer middleware: it binds each verdict to a frozen snapshot and reserves per-tool quota before asynchronous approval or execution, but it cannot defend a process that mutates memory or bypasses the wrapped executor.

## Tests

```sh
npm test         # 314 Node unit tests (engine, policy and guard parity, craft)
npm run audit    # headless Chrome audit at 1440x900, 820x1180 and 390x844
```

The browser audit drives the real UI with pointer clicks and key presses. It checks overflow and touch targets in both themes, keyboard flows, the obfuscation fuzzer, an XSS payload that must stay inert, invalid and valid policy edits, guard and policy downloads (the downloaded guard is then imported and run in Node), a one-page US Letter print in both themes, reduced motion, reload restore, and zero console errors, failed requests or outside requests.

## Project layout

| Path | What it holds |
| --- | --- |
| `js/deobfuscate.mjs` | Invisible-character, entity, percent, NFKC, homoglyph and payload decoding |
| `js/netguard.mjs` | URL, IP range, punycode, homoglyph host and exfiltration checks |
| `js/pathguard.mjs` | Path canonicalization, sensitive and persistence paths |
| `js/shell.mjs` | Shell lexer and danger classifier |
| `js/injection.mjs` | Prompt-injection signal scoring |
| `js/policy.mjs` | Tool catalog, rules, presets, validation, provenance and `evaluateCall` |
| `js/engine.mjs` | Trace replay, taint graph and benchmark metrics |
| `js/compiler.mjs` | Builds `shieldgraph-guard.mjs` from the detector sources |
| `js/scenarios.mjs` | The 14 labeled scenarios |
| `js/app.mjs`, `js/graph.mjs`, `js/report.mjs`, `js/texttrace.mjs` | Workbench UI, SVG flow graph, printable audit sheet, text trace rendering |
| `fonts/shieldgraph-plot.woff2` | ShieldGraph Plot, the monoline display face, drawn by `tools/build-font.py` |
| `tests/` | Unit, parity, craft and browser audit suites |

## License

MIT. ShieldGraph Plot is drawn from scratch in `tools/build-font.py` and shares the same license.
