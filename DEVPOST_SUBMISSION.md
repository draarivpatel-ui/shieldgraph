# ShieldGraph

Track. AI, Agentic Systems, Cybersecurity, and Dev Tools

## Elevator pitch

A browser-native firewall for AI agent tool calls. It checks arguments for untrusted text-match evidence, labels unmatched arguments `origin not established`, decodes hidden payloads, and compiles your policy into middleware you can run.

## Inspiration

AI agents now read web pages, emails, READMEs and tool output, then act with real tools like a shell, an HTTP client, an inbox or a payment API. That makes indirect prompt injection a security problem rather than a chatbot quirk. A poisoned README can tell a coding agent to pipe a remote script into bash. An email can ask an inbox assistant to wire money. A webhook can point an agent at the cloud metadata address. Most guardrails look at the model's text. ShieldGraph looks at the tool call, the moment the agent touches the world, and asks whether each argument carries untrusted text it should not.

## What it does

ShieldGraph replays an agent trace and draws it as a live flow graph with four columns (inputs, planner, tool calls, effects). Dashed purple edges show taint, meaning an argument that was copied from untrusted content. Each tool call gets a verdict of Allowed, Logged, Needs approval or Blocked, with a risk score and the exact rules that fired.

- **Taint lineage.** Values the user typed are endorsed. Values copied from a web page, email, README, PDF or webhook are tainted, even when they only appear after decoding.
- **De-obfuscation.** Zero-width characters, Unicode tag smuggling, HTML entities, double percent-encoding, fullwidth letters, Cyrillic lookalikes, Base64 and hex are peeled off in order, and the inspector shows each layer with a before and after view.
- **SSRF and egress guard.** Decimal, octal and hex IP tricks, IPv4-mapped IPv6, cloud metadata hosts, `user@host` confusion, punycode lookalike domains, secrets in query strings and data hidden in DNS labels.
- **Path and shell guards.** Workspace escape with encoded dot segments, credential files, git hooks and shell rc persistence, pipe-to-shell, reverse shells, payloads hidden inside `sh -c` or `$( )` wrappers, and shell operators that came from untrusted text.
- **Confused-deputy checks.** A payment or email can only go to an account or address the user actually named.
- **Red-team playground.** Edit any payload or tool call and the verdict updates as you type. One-click fuzz buttons re-encode the payload as Base64, zero-width splits, homoglyphs, percent-encoding or HTML entities so you can watch the detectors still catch it.
- **Benchmark.** Fourteen scenarios, ten attacks and four ordinary developer workflows, with every tool call labeled by hand. Switching between the Permissive, Balanced and Zero-Trust presets, or editing rules live, recomputes precision, recall, F1 and the false positive rate.
- **Policy compiler.** Edit the JSON manifest or flip rule actions in a table, then export a runnable `shieldgraph-guard.mjs`, the policy JSON, and a one-page printable security audit sheet.

| Policy | Malicious calls caught | Benign calls interrupted | Precision | Recall | F1 | False positive rate | Denied | Held for approval |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Permissive | 3/15 | 0/14 | 1.00 | 0.20 | 0.33 | 0% | 3 | 0 |
| Balanced | 15/15 | 0/14 | 1.00 | 1.00 | 1.00 | 0% | 14 | 1 |
| Zero-Trust | 15/15 | 8/14 | 0.65 | 1.00 | 0.79 | 57% | 21 | 2 |

The Balanced score is measured on scenarios written by the same author as the detectors, so it shows coverage of these attack shapes, not proof that it generalizes. Three attacks that Balanced misses today are pinned in the test suite and listed in the README. Provenance matching and injection scoring are text heuristics, not cryptographic identity, sandboxing or OS-level authorization. The exported run() middleware binds each verdict to a frozen snapshot and reserves per-tool quota before asynchronous approval or execution, but the wrapped executor still has to be the only execution path.

## How we built it

ShieldGraph is plain JavaScript ES modules, HTML and CSS with zero dependencies, no external requests and no model calls. The browser fetches only same-origin static files, including the detector module sources needed to compile a guard export; guard and policy exports are generated locally as downloads. Node.js 22 or newer runs the test harness and generated middleware. The detectors are small pure modules (de-obfuscation, network, path, shell, injection) feeding one decision function, `evaluateCall`. The guard compiler concatenates those same modules into a single file and appends the policy and a small runtime, so the exported middleware and the on-screen verdicts come from identical code. A parity test imports the compiled guard for every preset and checks it against the engine on all 29 tool calls.

The flow graph is hand-built SVG, the display face ShieldGraph Plot is a monoline font drawn stroke by stroke with a Python script, and the page runs under a strict Content Security Policy with no inline script and no markup ever built from payload text.

Testing covers 314 Node unit tests (including bypass attempts, benign false-positive cases, guard parity, WCAG contrast computed from the real color tokens, and a scanner that proves itself on planted probes) plus a headless Chrome audit at desktop, tablet and phone sizes that clicks through every view, runs the fuzzer and an XSS payload, downloads the guard and runs it in Node, and checks the audit sheet prints on exactly one US Letter page.

## Challenges we ran into

False positives were harder than detection. A git SHA and an npm integrity hash both look like encoded blobs, the word "ignore" shows up in ordinary docs, and `npm ci && npm test` uses the same operators as a command injection. The fixes were principled rather than special-cased. Decoded payloads must read as text, injection patterns need the full shape of an override, and shell operators only count as injection when they arrived inside untrusted content.

## Accomplishments that we're proud of

The guard you download is the same code that drew the verdicts on screen, and a parity test checks it on every tool call. The benchmark table above is recomputed by the app, and a test fails if the two ever disagree.

## What we learned

Provenance is a stronger signal than wording. Attackers can rephrase an instruction forever, but the payee account, the URL or the shell operator still has to come from somewhere, and the firewall can see where.

## What's next for ShieldGraph

A resolving egress proxy to close the DNS rebinding gap, adapters for common agent frameworks, and a larger shared scenario corpus written by people other than the detector author.

## Built with

JavaScript, HTML, CSS, SVG, Node.js test runner, Chrome DevTools Protocol, Python and fontTools for the custom font. AI assistance (Claude by Anthropic) was used as a coding assistant during development.
