# DSH Security Suite

> [English](README.md) · [中文](README.zh-CN.md)

A native security assessment suite for
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH),
adapted from the architecture of
[openai/codex-security](https://github.com/openai/codex-security) (Apache-2.0).

It runs repository, diff, and deep security scans inside DSH: **LLM review
subagents do the discovery** (baseline auditors, focused investigators,
file-review and deep workers), while a deterministic engine produces the
evidence baseline, and every reportable finding is bound to a claim-token
validation receipt and an attack-path receipt before it can be finalized.

## Quick start

```sh
npm install
npm run build
dsh plugin --profile web add /absolute/path/to/dsh-security-suite
```

```sh
dsh run "Run a deep security scan, validate candidates, trace attack paths, and produce a report for this workspace."
```

## Capabilities

| Workflow | What it does |
| --- | --- |
| Standard scan | One independent baseline auditor plus focused investigator DSH subagents over source-backed investigation packets (`security_scan`, default `discovery: llm`) |
| Diff scan | One restricted file-review subagent per changed file, anchored to the changed code (`security_review_diff`, default `discovery: llm`) |
| Deep scan | Six workers per round, each with a distinct review lens, a semantic reducer per round, and stop-after-no-new saturation |
| Deterministic fallback | The rule/AST/flow engine remains available via `discovery: engine` and still produces the receipt baseline |
| Validation & attack paths | Claim-token-bound validation and attack-path receipts; isolated runtime evidence with snapshot checks |
| Tracking | GitHub / Jira / Linear issues and private GitHub draft advisories with preview, duplicate lookup, and readback |
| Triage & backlog | Import GitHub REST findings or Jira/Linear tickets, triage against local source evidence |
| Remediation | Reviewed, approval-gated, atomic multi-file patches with rollback and verification scans |
| Exports | Markdown, JSON, SARIF, CSV; canonical `scan-manifest.json` / `findings.json` / `coverage.json` |
| Extras | Threat models, vulnerability write-ups, hardening portfolios, disclosure campaigns, bulk scans, pre-commit hook |

See the full tool surface and evidence model in
[docs/evidence-contract.md](docs/evidence-contract.md).

## How discovery works

- **Standard (`discovery: llm`, default)**: the plugin freezes an in-scope
  worklist from scan receipts, launches one independent baseline auditor
  subagent, builds a source-backed threat map, groups review questions into
  investigation packets, and runs one focused investigator subagent per
  packet. Every candidate must cite a receipted in-scope location.
- **Diff (`discovery: llm`, default)**: each changed source file is assigned
  to one restricted file-review subagent that reads it in full.
- **Deep**: six workers per round with distinct lenses (forward dataflow,
  backward from sinks, authorization logic, open-ended, parsers, secrets)
  review immutable 200-line regions; a semantic reducer subagent merges
  equivalent candidates across workers; saturation requires
  `stopAfterNoNew` consecutive zero-novelty rounds.
- **Engine (`discovery: engine`)**: the deterministic rule/AST/flow engine for
  JS/TS, Python, Go, Java, C#, PHP, Ruby, C, C++, and Rust.

Discovery never auto-confirms vulnerabilities. A finding becomes reportable
only after a source-backed validation receipt and a separately claimed
attack-path receipt.

## Configuration

```yaml
config:
  enabled: true
  maxFiles: 500
  maxFileBytes: 262144
  deepScan:                 # deep-scan engine (codex-security semantics)
    workers: auto           # positive integer, or 'auto' (capped at 6)
    stopAfterNoNew: 6       # saturate after this many zero-novelty rounds
    maxDiscoveryRuns: 60
    maxTimeHours: 96
  knowledgeBase: []         # files/dirs of Markdown or plain text, read-only
  scanPrompt: ''            # extra instructions for every LLM discovery worker
```

State is placed under `DSH_SECURITY_SUITE_STATE_DIR` or `stateDir`
(default `~/.dsh-security-suite`); the engine confines repository and
knowledge-base paths to the active workspace.

## Documentation

- [docs/evidence-contract.md](docs/evidence-contract.md) — the evidence model,
  receipts, coverage semantics, and per-rule analysis boundaries
- [MIGRATION.md](MIGRATION.md) — the codex-security capability matrix and
  migration status

## Attribution

Worker prompt templates, canonical scan-contract field trees, severity policy,
and deep-scan configuration semantics are adapted from
[openai/codex-security](https://github.com/openai/codex-security) (Apache-2.0).
No third-party security-runtime source code or dependency is executed.

## License

Apache-2.0.
