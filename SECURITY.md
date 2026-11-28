# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/shieldgraph/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| latest `main` | Supported |

Security fixes are applied to the latest state of the default branch.

## Scope

This policy covers the static ShieldGraph browser application, including agent tool-call policy evaluation, prompt-injection detection, deobfuscation, graph rendering, report output and downloadable guard generation.

In scope:

- A cross-site scripting or HTML injection path through scenario text, decoded payloads, graph labels, policy data, traces, imports or report output.
- A policy-engine bypass that allows a prohibited tool call, key read, network egress path or shell action to be marked as allowed.
- A prompt-injection, encoded-payload or deobfuscation flaw that hides active content from the detector or causes unbounded resource use.
- A report, policy export or generated guard flaw that injects attacker-controlled code or misrepresents the selected protections.
- A browser audit or local server boundary flaw that sends repository data to an external service.

Out of scope:

- Browser vulnerabilities, operating system compromise or physical access to the machine.
- Damage caused by modified copies of the static application that do not come from this repository.
- Intentionally hostile red-team fixture text when it remains inside the documented workbench boundary.

## Coordinated disclosure

- Acknowledgment: within 3 business days.
- Initial triage: within 14 calendar days.
- Fix or mitigation target: within 90 calendar days for confirmed reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
