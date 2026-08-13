# DSH Security Suite

`dsh-security-suite` brings the security-review methodology of [OpenAI Codex Security](https://github.com/openai/codex-security) to [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) as a native Cordis bundle.

> DeepSeek Harness is in developer preview; its plugin API may introduce breaking changes.

It is an independent implementation, not a wrapper around Codex Security's CLI. It migrates the Codex Security methodology and artifact model to DSH's Cordis runtime. The DSH agent supplies source-level reasoning and validation; tools persist the evidence, findings, reports, and review state.

## Capability Matrix

| Codex Security workflow | DSH Security Suite capability |
| --- | --- |
| Standard and scoped scan | `security_scan` (`standard`) and `security_assess` |
| Git diff scan | `security_review_diff` |
| Deep scan | `security_scan` (`deep`) plus the guided multi-pass workflow |
| Threat model and policy | `security_threat_model_template` and the security workflow prompt |
| Discovery, validation, attack paths, triage | Canonical findings from `security_get_scan`, persisted with `security_update_finding` |
| False-positive state and scan history | `security_update_finding`, `security_scan_history`, `security_compare_scans` |
| Vulnerability reports | `security_finding_writeup` and `security_export_scan` (Markdown/JSON/SARIF/CSV) |
| Fix and hardening proposals | Guided DSH workflow. Source edits remain explicit user-authorized actions. |
| GitHub, Jira, Linear tracking | `security_tracking_preview`; it produces an exact payload but never writes externally without a separate user-approved integration. |

The plugin does not embed OpenAI's proprietary Codex scanning service, credential handling, or hosted external connectors. It therefore does not claim to reproduce their execution environment or create third-party tickets automatically. It retains the workflow, evidence, canonical result, export, and approval boundaries in DSH.

## Install

Build the package, then add it to every profile where it should be available:

```sh
npm install
npm run build
dsh plugin --profile web add /absolute/path/to/dsh-security-suite
dsh plugin --profile headless add /absolute/path/to/dsh-security-suite
```

Verify the profile composition and run a scan:

```sh
dsh --profile web --dump-config
dsh run "Run a deep security scan, validate candidates, trace attack paths, and produce a report for this workspace."
```

## Configuration

The bundle row accepts these settings:

```yaml
config:
  enabled: true
  maxFiles: 500
  maxFileBytes: 262144
```

Scans only read source files inside the current workspace. They ignore dependency and build directories, limit file count and size, reject paths outside the workspace, and write state under the system temporary directory by default. Set `DSH_SECURITY_SUITE_STATE_DIR` or `stateDir` to retain scan history in a selected directory outside the target repository. Pattern-discovered results are candidate evidence, not vulnerability verdicts: validate them with source-backed attacker-to-sink analysis before reporting or tracking.

## Attribution

This project adapts the workflow concepts of [OpenAI Codex Security](https://github.com/openai/codex-security), which is licensed under Apache-2.0. No upstream source code is copied into this repository.

## License

Apache-2.0.
